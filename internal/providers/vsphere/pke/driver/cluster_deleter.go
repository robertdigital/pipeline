// +build 0

// Copyright © 2019 Banzai Cloud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package driver

import (
	"context"
	"net/http"
	"time"

	"emperror.dev/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.uber.org/cadence"
	"go.uber.org/cadence/client"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/banzaicloud/pipeline/src/auth"
	"github.com/banzaicloud/pipeline/config"
	"github.com/banzaicloud/pipeline/internal/cluster/metrics"
	"github.com/banzaicloud/pipeline/internal/providers/vsphere/pke"
	"github.com/banzaicloud/pipeline/internal/providers/vsphere/pke/workflow"
	intSecret "github.com/banzaicloud/pipeline/internal/secret"
	pkgCluster "github.com/banzaicloud/pipeline/pkg/cluster"
	"github.com/banzaicloud/pipeline/pkg/k8sclient"
	pkgVsphere "github.com/banzaicloud/pipeline/pkg/providers/vsphere"
	"github.com/banzaicloud/pipeline/src/secret"
)

func MakeVspherePKEClusterDeleter(events ClusterDeleterEvents, kubeProxyCache KubeProxyCache, logger logrus.FieldLogger, secrets SecretStore, statusChangeDurationMetric metrics.ClusterStatusChangeDurationMetric, store pke.VspherePKEClusterStore, workflowClient client.Client) VspherePKEClusterDeleter {
	return VspherePKEClusterDeleter{
		events:                     events,
		kubeProxyCache:             kubeProxyCache,
		logger:                     logger,
		secrets:                    secrets,
		statusChangeDurationMetric: statusChangeDurationMetric,
		store:                      store,
		workflowClient:             workflowClient,
	}
}

type VspherePKEClusterDeleter struct {
	events                     ClusterDeleterEvents
	kubeProxyCache             KubeProxyCache
	logger                     logrus.FieldLogger
	secrets                    SecretStore
	statusChangeDurationMetric metrics.ClusterStatusChangeDurationMetric
	store                      pke.VspherePKEClusterStore
	workflowClient             client.Client
}

type SecretStore interface {
	Get(orgnaizationID uint, secretID string) (*secret.SecretItemResponse, error)
}

type ClusterDeleterEvents interface {
	ClusterDeleted(organizationID uint, clusterName string)
}

type KubeProxyCache interface {
	Delete(clusterUID string)
}

func (cd VspherePKEClusterDeleter) Delete(ctx context.Context, cluster pke.PKEOnVsphereCluster, forced bool) error {
	logger := cd.logger.WithField("clusterName", cluster.Name).WithField("clusterID", cluster.ID).WithField("forced", forced)
	logger.Info("Deleting cluster")

	pipNames, err := collectPublicIPAddressNames(ctx, logger, cd.secrets, cluster, forced)
	if err != nil {
		return errors.WrapIf(err, "failed to collect public IP address resource names")
	}

	input := workflow.DeleteClusterWorkflowInput{
		OrganizationID:       cluster.OrganizationID,
		SecretID:             cluster.SecretID,
		ClusterID:            cluster.ID,
		ClusterName:          cluster.Name,
		ClusterUID:           cluster.UID,
		K8sSecretID:          cluster.K8sSecretID,
		ResourceGroupName:    cluster.ResourceGroup.Name,
		LoadBalancerName:     cluster.Name, // must be the same as the value passed to pke install master --kubernetes-cluster-name
		PublicIPAddressNames: pipNames,
		RouteTableName:       pke.GetRouteTableName(cluster.Name),
		ScaleSetNames:        getVMSSNames(cluster),
		SecurityGroupNames:   []string{cluster.Name + "-master-nsg", cluster.Name + "-worker-nsg"},
		VirtualNetworkName:   cluster.VirtualNetwork.Name,
		Forced:               forced,
	}

	retryPolicy := &cadence.RetryPolicy{
		InitialInterval:    time.Second * 3,
		BackoffCoefficient: 2,
		ExpirationInterval: time.Minute * 3,
		MaximumAttempts:    5,
	}

	workflowOptions := client.StartWorkflowOptions{
		TaskList:                     "pipeline",
		ExecutionStartToCloseTimeout: 40 * time.Minute, // TODO: lower timeout
		RetryPolicy:                  retryPolicy,
	}

	if err := cd.store.SetStatus(cluster.ID, pkgCluster.Deleting, pkgCluster.DeletingMessage); err != nil {
		return errors.WrapIf(err, "failed to set cluster status")
	}

	timer, err := cd.getClusterStatusChangeDurationTimer(cluster)
	if err = errors.WrapIf(err, "failed to start status change duration metric timer"); err != nil {
		if forced {
			cd.logger.Error(err)
			timer = metrics.NoopDurationMetricTimer{}
		} else {
			return err
		}
	}

	wfrun, err := cd.workflowClient.ExecuteWorkflow(ctx, workflowOptions, workflow.DeleteClusterWorkflowName, input)
	if err = errors.WrapIfWithDetails(err, "failed to start cluster deletion workflow", "cluster", cluster.Name); err != nil {
		_ = cd.store.SetStatus(cluster.ID, pkgCluster.Error, err.Error())
		return err
	}

	go func() {
		defer timer.RecordDuration()

		ctx := context.Background()

		if err := wfrun.Get(ctx, nil); err != nil {
			cd.logger.Errorf("cluster deleting workflow failed: %v", err)
			return
		}
		cd.kubeProxyCache.Delete(cluster.UID)
		cd.events.ClusterDeleted(cluster.OrganizationID, cluster.Name)
	}()

	if err = cd.store.SetActiveWorkflowID(cluster.ID, wfrun.GetID()); err != nil {
		return errors.WrapIfWithDetails(err, "failed to set active workflow ID for cluster", "cluster", cluster.Name, "workflowID", wfrun.GetID())
	}

	return nil
}

func (cd VspherePKEClusterDeleter) getClusterStatusChangeDurationTimer(cluster pke.PKEOnVsphereCluster) (metrics.DurationMetricTimer, error) {
	values := metrics.ClusterStatusChangeDurationMetricValues{
		ProviderName: pkgCluster.Vsphere,
		LocationName: cluster.Location,
		Status:       pkgCluster.Deleting,
	}
	if viper.GetBool(config.MetricsDebug) {
		org, err := auth.GetOrganizationById(cluster.OrganizationID)
		if err != nil {
			return nil, errors.WrapIf(err, "Error during getting organization.")
		}
		values.OrganizationName = org.Name
		values.ClusterName = cluster.Name
	}
	return cd.statusChangeDurationMetric.StartTimer(values), nil
}

func (cd VspherePKEClusterDeleter) DeleteByID(ctx context.Context, clusterID uint, forced bool) error {
	cl, err := cd.store.GetByID(clusterID)
	if err != nil {
		return errors.WrapIf(err, "failed to load cluster from data store")
	}
	return cd.Delete(ctx, cl, forced)
}

func collectPublicIPAddressNames(ctx context.Context, logger logrus.FieldLogger, secrets SecretStore, cluster pke.PKEOnVsphereCluster, forced bool) ([]string, error) {
	sir, err := secrets.Get(cluster.OrganizationID, cluster.SecretID)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to get cluster secret from secret store")
	}
	cc, err := pkgVsphere.NewCloudConnection(&vsphere.PublicCloud, pkgVsphere.NewCredentials(sir.Values))
	if err != nil {
		return nil, errors.WrapIf(err, "failed to create cloud connection")
	}

	names := make(map[string]bool)

	lb, err := cc.GetLoadBalancersClient().Get(ctx, cluster.ResourceGroup.Name, pke.GetLoadBalancerName(cluster.Name), "frontendIPConfigurations/publicIPAddress")
	if err != nil {
		if lb.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, errors.WrapIf(err, "failed to retrieve load balancer")
	}
	names = gatherOwnedPublicIPAddressNames(lb, cluster.Name, names)

	names, err = gatherK8sServicePublicIPs(ctx, cc.GetPublicIPAddressesClient(), cluster, secrets, names)
	if err = errors.WrapIf(err, "failed to gather k8s services' public IP addresses"); err != nil {
		if forced {
			logger.Warning(err)
		} else {
			return nil, err
		}
	}

	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	return result, nil
}

func gatherOwnedPublicIPAddressNames(lb network.LoadBalancer, clusterName string, names map[string]bool) map[string]bool {
	if names == nil {
		names = make(map[string]bool)
	}

	if lb.LoadBalancerPropertiesFormat != nil {
		if fics := lb.LoadBalancerPropertiesFormat.FrontendIPConfigurations; fics != nil {
			for _, fic := range *fics {
				if fic.FrontendIPConfigurationPropertiesFormat != nil {
					if pip := fic.FrontendIPConfigurationPropertiesFormat.PublicIPAddress; pip != nil {
						if name := to.String(pip.Name); name != "" && workflow.HasOwnedTag(clusterName, to.StringMap(pip.Tags)) {
							names[name] = true
						}
					}
				}
			}
		}
	}

	return names
}

func gatherK8sServicePublicIPs(ctx context.Context, client *pkgVsphere.PublicIPAddressesClient, cluster pke.PKEOnVsphereCluster, secrets SecretStore, names map[string]bool) (map[string]bool, error) {
	if cluster.K8sSecretID == "" {
		return names, nil
	}

	k8sConfig, err := intSecret.MakeKubeSecretStore(secrets).Get(cluster.OrganizationID, cluster.K8sSecretID)
	if err != nil {
		return names, errors.WrapIf(err, "failed to get k8s config")
	}

	resPage, err := client.List(ctx, cluster.ResourceGroup.Name)
	if err != nil {
		return names, errors.WrapIfWithDetails(err, "failed to list Vsphere public IP address resources in resource group", "resourceGroup", cluster.ResourceGroup.Name)
	}

	ipToName := make(map[string]string)
	for {
		for _, pip := range resPage.Values() {
			if to.String(pip.Name) != "" && to.String(pip.IPAddress) != "" {
				ipToName[to.String(pip.IPAddress)] = to.String(pip.Name)
			}
		}
		if resPage.NotDone() {
			if err := resPage.NextWithContext(ctx); err != nil {
				return nil, err
			}
		} else {
			break
		}
	}

	k8sClient, err := k8sclient.NewClientFromKubeConfig(k8sConfig)
	if err != nil {
		return names, errors.WrapIf(err, "failed to create a new Kubernetes client")
	}

	serviceList, err := k8sClient.CoreV1().Services(metav1.NamespaceAll).List(metav1.ListOptions{})
	if serviceList == nil || err != nil {
		return names, errors.WrapIf(err, "failed to retrieve service list")
	}

	if names == nil {
		names = make(map[string]bool)
	}

	for _, service := range serviceList.Items {
		if service.Spec.Type == corev1.ServiceTypeLoadBalancer {
			for _, ing := range service.Status.LoadBalancer.Ingress {
				if name := ipToName[ing.IP]; name != "" {
					names[name] = true
				}
			}
		}
	}

	return names, nil
}

func getVMSSNames(cluster pke.PKEOnVsphereCluster) []string {
	names := make([]string, len(cluster.NodePools))
	for i, np := range cluster.NodePools {
		names[i] = pke.GetVMSSName(cluster.Name, np.Name)
	}
	return names
}
