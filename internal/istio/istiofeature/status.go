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

package istiofeature

import (
	"context"
	"strconv"

	"emperror.dev/errors"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/banzaicloud/istio-operator/pkg/apis/istio/v1beta1"
)

func (m *MeshReconciler) GetClusterStatus() (map[uint]string, error) {
	status := make(map[uint]string, 0)

	client, err := m.getMasterRuntimeK8sClient()
	if err != nil {
		return nil, errors.WrapIf(err, "could not get istio operator client")
	}

	var istios v1beta1.IstioList
	err = client.List(context.Background(), &istios, runtimeclient.InNamespace(istioOperatorNamespace))
	if err != nil {
		return nil, errors.WrapIf(err, "could not list istio CRs")
	}
	for _, istio := range istios.Items {
		labels := istio.GetLabels()
		if len(labels) == 0 {
			continue
		}

		cID := istio.Labels[clusterIDLabel]
		if cID == "" {
			continue
		}

		clusterID, err := strconv.ParseUint(cID, 10, 64)
		if err != nil {
			m.errorHandler.Handle(errors.WithStack(err))
			continue
		}

		status[uint(clusterID)] = string(istio.Status.Status)
	}

	var remoteistios v1beta1.RemoteIstioList
	err = client.List(context.Background(), &remoteistios, runtimeclient.InNamespace(istioOperatorNamespace))
	if err != nil {
		return nil, errors.WrapIf(err, "could not list Remote istio CRs")
	}
	for _, remoteistio := range remoteistios.Items {
		labels := remoteistio.GetLabels()
		if len(labels) == 0 {
			continue
		}

		cID := remoteistio.Labels[clusterIDLabel]
		if cID == "" {
			continue
		}

		clusterID, err := strconv.ParseUint(cID, 10, 64)
		if err != nil {
			m.errorHandler.Handle(errors.WithStack(err))
			continue
		}

		status[uint(clusterID)] = string(remoteistio.Status.Status)
	}

	return status, nil
}
