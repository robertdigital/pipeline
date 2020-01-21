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

package pkeworkflow

import (
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/Masterminds/semver"
	"go.uber.org/cadence/workflow"
	"go.uber.org/zap"
)

const CreateClusterWorkflowName = "pke-create-cluster"
const pkeVersion = "0.4.20"

func getDefaultImageID(region, kubernetesVersion string) (string, error) {
	constraint114, err := semver.NewConstraint("~1.14.0")
	if err != nil {
		return "", errors.Wrap(err, "could not create semver constraint for Kubernetes version 1.14+")
	}

	constraint115, err := semver.NewConstraint("~1.15.0")
	if err != nil {
		return "", errors.Wrap(err, "could not create semver constraint for Kubernetes version 1.15+")
	}

	constraint116, err := semver.NewConstraint("~1.16.0")
	if err != nil {
		return "", errors.Wrap(err, "could not create semver constraint for Kubernetes version 1.16+")
	}

	constraint117, err := semver.NewConstraint("~1.17.0")
	if err != nil {
		return "", errors.Wrap(err, "could not create semver constraint for Kubernetes version 1.17+")
	}

	kubeVersion, err := semver.NewVersion(kubernetesVersion)
	if err != nil {
		return "", errors.WithDetails(err, "could not create semver from Kubernetes version", "kubernetesVersion", kubernetesVersion)
	}

	switch {
	case constraint114.Check(kubeVersion):
		return map[string]string{
			"ap-east-1":      "ami-006502ed43c36f1e0", // Asia Pacific (Hong Kong).
			"ap-northeast-1": "ami-06b79d0ef4c299d15", // Asia Pacific (Tokyo).
			"ap-northeast-2": "ami-00917002b22a5eaca", // Asia Pacific (Seoul).
			"ap-southeast-1": "ami-0699853ac47eb0175", // Asia Pacific (Mumbai).
			"ap-southeast-2": "ami-04643737f234b7cbe", // Asia Pacific (Singapore).
			"ap-south-1":     "ami-066dc3074af614d50", // Asia Pacific (Sydney).
			"ca-central-1":   "ami-0250c7c8a2327cff9", // Canada (Central).
			"eu-central-1":   "ami-0262cb8ddc17aec3e", // EU (Frankfurt).
			"eu-north-1":     "ami-05a2faa4135c3ffc0", // EU (Stockholm).
			"eu-west-1":      "ami-0963cc3135ef6050f", // EU (Ireland).
			"eu-west-2":      "ami-0b7eb3d3d73bed69b", // EU (London).
			"eu-west-3":      "ami-05bb8d1aef64fe0af", // EU (Paris).
			"me-south-1":     "ami-00b950d5c66e8fb95", // Middle East (Bahrain).
			"sa-east-1":      "ami-02c253419683aa2c8", // South America (Sao Paulo)
			"us-east-1":      "ami-01839e8c6bd95881c", // US East (N. Virginia).
			"us-east-2":      "ami-020250a080ebb188f", // US East (Ohio).
			"us-west-1":      "ami-0cafcb1bcf45153b8", // US West (N. California).
			"us-west-2":      "ami-01e516ad29fa3f529", // US West (Oregon).
		}[region], nil
	case constraint115.Check(kubeVersion):
		return map[string]string{
			"ap-east-1":      "ami-0e68783263a9cf78d", // Asia Pacific (Hong Kong).
			"ap-northeast-1": "ami-071e8a5f173e27c91", // Asia Pacific (Tokyo).
			"ap-northeast-2": "ami-0642216b8945ff064", // Asia Pacific (Seoul).
			"ap-southeast-1": "ami-0c8d4a8f06fdf6985", // Asia Pacific (Mumbai).
			"ap-southeast-2": "ami-0c9da81852ed80a4d", // Asia Pacific (Singapore).
			"ap-south-1":     "ami-084cd316e932210e5", // Asia Pacific (Sydney).
			"ca-central-1":   "ami-0dc557b6e2afcbe1c", // Canada (Central).
			"eu-central-1":   "ami-0510259b123b721dd", // EU (Frankfurt).
			"eu-north-1":     "ami-03c1e19992e372497", // EU (Stockholm).
			"eu-west-1":      "ami-0de02e98881a51053", // EU (Ireland).
			"eu-west-2":      "ami-06857a6dd2f0d0b06", // EU (London).
			"eu-west-3":      "ami-051696b266427c5d0", // EU (Paris).
			"me-south-1":     "ami-02e0b86a2bbd7af80", // Middle East (Bahrain).
			"sa-east-1":      "ami-0fa22db8555af068d", // South America (Sao Paulo)
			"us-east-1":      "ami-00e84f2147ea05b7d", // US East (N. Virginia).
			"us-east-2":      "ami-06a2ea25f36e8d71e", // US East (Ohio).
			"us-west-1":      "ami-037ec3d09188ce2e8", // US West (N. California).
			"us-west-2":      "ami-04f69475931368929", // US West (Oregon).
		}[region], nil
	case constraint116.Check(kubeVersion):
		return map[string]string{
			"ap-east-1":      "ami-04747c7e79d680861", // Asia Pacific (Hong Kong).
			"ap-northeast-1": "ami-073d36d2adbe8df22", // Asia Pacific (Tokyo).
			"ap-northeast-2": "ami-044dc3710aec6bda2", // Asia Pacific (Seoul).
			"ap-southeast-1": "ami-0f2df6c8904cea273", // Asia Pacific (Mumbai).
			"ap-southeast-2": "ami-0847661b0ea0a16f3", // Asia Pacific (Singapore).
			"ap-south-1":     "ami-0ffde937c97549195", // Asia Pacific (Sydney).
			"ca-central-1":   "ami-098796bfbc41f56e4", // Canada (Central).
			"eu-central-1":   "ami-0694a7ff505c8ed29", // EU (Frankfurt).
			"eu-north-1":     "ami-0ada97dcd3204440e", // EU (Stockholm).
			"eu-west-1":      "ami-0c99ebf013429a613", // EU (Ireland).
			"eu-west-2":      "ami-02ed905f5b04c3854", // EU (London).
			"eu-west-3":      "ami-0cde39fa998412e45", // EU (Paris).
			"me-south-1":     "ami-07b0665efde3f138d", // Middle East (Bahrain).
			"sa-east-1":      "ami-08d6c6c053330f17d", // South America (Sao Paulo)
			"us-east-1":      "ami-0ef61beb3758fe352", // US East (N. Virginia).
			"us-east-2":      "ami-0db2f094dc2e2bee0", // US East (Ohio).
			"us-west-1":      "ami-014230d9402b8d24a", // US West (N. California).
			"us-west-2":      "ami-0e6b60ca96ed4b14d", // US West (Oregon).
		}[region], nil
	case constraint117.Check(kubeVersion):
		return map[string]string{
			"ap-east-1":      "ami-05efbc5ab88627782", // Asia Pacific (Hong Kong).
			"ap-northeast-1": "ami-029e9ba67ee82dc4d", // Asia Pacific (Tokyo).
			"ap-northeast-2": "ami-0b65e717fe249c0ff", // Asia Pacific (Seoul).
			"ap-southeast-1": "ami-0cfb85f0e835e6383", // Asia Pacific (Mumbai).
			"ap-southeast-2": "ami-07c71ce7e60f7bc62", // Asia Pacific (Singapore).
			"ap-south-1":     "ami-0d92f5d7671a5dcff", // Asia Pacific (Sydney).
			"ca-central-1":   "ami-039475a379637e8fe", // Canada (Central).
			"eu-central-1":   "ami-040427722442fc2da", // EU (Frankfurt).
			"eu-north-1":     "ami-052de689064e9f8dd", // EU (Stockholm).
			"eu-west-1":      "ami-015c5cce5437e3e4d", // EU (Ireland).
			"eu-west-2":      "ami-065fcd206187b9ab4", // EU (London).
			"eu-west-3":      "ami-015dca36371402365", // EU (Paris).
			"me-south-1":     "ami-0ddf598d13adaccaf", // Middle East (Bahrain).
			"sa-east-1":      "ami-076dd78575e897e72", // South America (Sao Paulo)
			"us-east-1":      "ami-083c6b4ab7ef0ad6e", // US East (N. Virginia).
			"us-east-2":      "ami-03bafcd2e99ea839d", // US East (Ohio).
			"us-west-1":      "ami-090ca189fb3845efc", // US West (N. California).
			"us-west-2":      "ami-0410cd92f04001ee0", // US West (Oregon).
		}[region], nil
	default:
		return map[string]string{
			"ap-east-1":      "ami-0c9680acbf35f26de", // Asia Pacific (Hong Kong).
			"ap-northeast-1": "ami-0f13e8123146595b9", // Asia Pacific (Tokyo).
			"ap-northeast-2": "ami-021015b95e7bdfbbe", // Asia Pacific (Seoul).
			"ap-southeast-1": "ami-0382298e181ef5686", // Asia Pacific (Mumbai).
			"ap-southeast-2": "ami-068231c38bc1a60f3", // Asia Pacific (Singapore).
			"ap-south-1":     "ami-016ec067d44808c4f", // Asia Pacific (Sydney).
			"ca-central-1":   "ami-0e06edb0102874198", // Canada (Central).
			"eu-central-1":   "ami-0ec8d2a455affc7e4", // EU (Frankfurt).
			"eu-north-1":     "ami-067696d723418ef5e", // EU (Stockholm).
			"eu-west-1":      "ami-0214421b4d7aaecdd", // EU (Ireland).
			"eu-west-2":      "ami-08576e40ab2877d2a", // EU (London).
			"eu-west-3":      "ami-0cb72921b642a83ec", // EU (Paris).
			"me-south-1":     "ami-0f5484e06a055b46d", // Middle East (Bahrain).
			"sa-east-1":      "ami-08d90516f7c661b6b", // South America (Sao Paulo).
			"us-east-1":      "ami-07079058aa890ee37", // US East (N. Virginia).
			"us-east-2":      "ami-0faf98ec1c0e28a7e", // US East (Ohio).
			"us-west-1":      "ami-0bef95b814eae1fc7", // US West (N. California).
			"us-west-2":      "ami-0ca6e0198325b7be7", // US West (Oregon).
		}[region], nil
	}
}

type TokenGenerator interface {
	GenerateClusterToken(orgID, clusterID uint) (string, string, error)
}

type CreateClusterWorkflowInput struct {
	OrganizationID              uint
	ClusterID                   uint
	ClusterUID                  string
	ClusterName                 string
	SecretID                    string
	Region                      string
	PipelineExternalURL         string
	PipelineExternalURLInsecure bool
	OIDCEnabled                 bool
	VPCID                       string
	SubnetID                    string
}

func CreateClusterWorkflow(ctx workflow.Context, input CreateClusterWorkflowInput) error {
	ao := workflow.ActivityOptions{
		ScheduleToStartTimeout: 10 * time.Minute,
		StartToCloseTimeout:    20 * time.Minute,
		WaitForCancellation:    true,
	}

	ctx = workflow.WithActivityOptions(ctx, ao)

	// Generate CA certificates
	{
		activityInput := GenerateCertificatesActivityInput{ClusterID: input.ClusterID}

		err := workflow.ExecuteActivity(ctx, GenerateCertificatesActivityName, activityInput).Get(ctx, nil)
		if err != nil {
			return err
		}
	}

	// Generic AWS activity input
	awsActivityInput := AWSActivityInput{
		OrganizationID: input.OrganizationID,
		SecretID:       input.SecretID,
		Region:         input.Region,
	}

	var rolesStackID string

	// Create AWS roles
	{
		activityInput := CreateAWSRolesActivityInput{AWSActivityInput: awsActivityInput, ClusterID: input.ClusterID}
		activityInput.AWSActivityInput.Region = "us-east-1"
		err := workflow.ExecuteActivity(ctx, CreateAWSRolesActivityName, activityInput).Get(ctx, &rolesStackID)
		if err != nil {
			return err
		}
	}

	var rolesOutput map[string]string

	// Wait for roles
	{
		if rolesStackID == "" {
			return errors.New("missing AWS role stack ID")
		}

		activityInput := WaitCFCompletionActivityInput{AWSActivityInput: awsActivityInput, StackID: rolesStackID}
		activityInput.AWSActivityInput.Region = "us-east-1"

		err := workflow.ExecuteActivity(ctx, WaitCFCompletionActivityName, activityInput).Get(ctx, &rolesOutput)
		if err != nil {
			return err
		}
	}

	var vpcStackID string

	// Create VPC
	{
		activityInput := CreateVPCActivityInput{
			AWSActivityInput: awsActivityInput,
			ClusterID:        input.ClusterID,
			ClusterName:      input.ClusterName,
			VPCID:            input.VPCID,
			SubnetID:         input.SubnetID,
		}
		err := workflow.ExecuteActivity(ctx, CreateVPCActivityName, activityInput).Get(ctx, &vpcStackID)
		if err != nil {
			return err
		}
	}

	var vpcOutput map[string]string

	// Wait for VPC
	{
		if vpcStackID == "" {
			return errors.New("missing VPC stack ID")
		}

		activityInput := WaitCFCompletionActivityInput{AWSActivityInput: awsActivityInput, StackID: vpcStackID}

		err := workflow.ExecuteActivity(ctx, WaitCFCompletionActivityName, activityInput).Get(ctx, &vpcOutput)
		if err != nil {
			return err
		}
	}

	// Get default security group of the VPC
	var vpcDefaultSecurityGroupID string

	activityInput := GetVpcDefaultSecurityGroupActivityInput{
		AWSActivityInput: awsActivityInput,
		ClusterID:        input.ClusterID,
		VpcID:            vpcOutput["VpcId"],
	}
	err := workflow.ExecuteActivity(ctx, GetVpcDefaultSecurityGroupActivityName, activityInput).Get(ctx, &vpcDefaultSecurityGroupID)
	if err != nil {
		return err
	}

	if vpcDefaultSecurityGroupID == "" {
		return errors.Errorf("couldn't get the default security group of the VPC %q", vpcOutput["VpcId"])
	}

	var nodePools []NodePool

	// List node pools
	{
		activityInput := ListNodePoolsActivityInput{ClusterID: input.ClusterID}
		err := workflow.ExecuteActivity(ctx, ListNodePoolsActivityName, activityInput).Get(ctx, &nodePools)
		if err != nil {
			return err
		}
	}

	var master NodePool
	for _, np := range nodePools {
		if np.Master {
			master = np
			if len(np.AvailabilityZones) <= 0 || np.AvailabilityZones[0] == "" {
				return errors.Errorf("missing availability zone for nodepool %q", np.Name)
			}
			break
		}
	}

	var keyOut UploadSSHKeyPairActivityOutput

	// Upload SSH key pair
	{
		activityInput := UploadSSHKeyPairActivityInput{
			ClusterID: input.ClusterID,
		}
		err := workflow.ExecuteActivity(ctx, UploadSSHKeyPairActivityName, activityInput).Get(ctx, &keyOut)
		if err != nil {
			return err
		}
	}

	// Create dex client for the cluster
	if input.OIDCEnabled {
		activityInput := CreateDexClientActivityInput{
			ClusterID: input.ClusterID,
		}
		err := workflow.ExecuteActivity(ctx, CreateDexClientActivityName, activityInput).Get(ctx, nil)
		if err != nil {
			return err
		}
	}

	var externalAddress string

	multiMaster := master.MaxCount > 1

	masterNodeSubnetID := strings.Split(vpcOutput["SubnetIds"], ",")[0]
	if len(master.Subnets) > 0 {
		masterNodeSubnetID = master.Subnets[0]
	}
	masterInput := CreateMasterActivityInput{
		ClusterID:                 input.ClusterID,
		VPCID:                     vpcOutput["VpcId"],
		VPCDefaultSecurityGroupID: vpcDefaultSecurityGroupID,
		SubnetID:                  masterNodeSubnetID,
		MultiMaster:               multiMaster,
		MasterInstanceProfile:     rolesOutput["MasterInstanceProfile"],
		ExternalBaseUrl:           input.PipelineExternalURL,
		ExternalBaseUrlInsecure:   input.PipelineExternalURLInsecure,
		Pool:                      master,
		SSHKeyName:                keyOut.KeyName,
		AvailabilityZone:          master.AvailabilityZones[0],
	}

	if multiMaster {
		// Create NLB
		var activityOutput CreateNLBActivityOutput
		activityInput := &CreateNLBActivityInput{
			AWSActivityInput: awsActivityInput,
			ClusterID:        input.ClusterID,
			ClusterName:      input.ClusterName,
			VPCID:            vpcOutput["VpcId"],
			SubnetIds:        []string{masterNodeSubnetID},
		}

		err := workflow.ExecuteActivity(ctx, CreateNLBActivityName, activityInput).Get(ctx, &activityOutput)
		if err != nil {
			return err
		}

		masterInput.TargetGroup = activityOutput.TargetGroup
		externalAddress = activityOutput.DNSName

	} else {

		// Create EIP
		var eip CreateElasticIPActivityOutput
		activityInput := &CreateElasticIPActivityInput{
			AWSActivityInput: awsActivityInput,
			ClusterID:        input.ClusterID,
			ClusterName:      input.ClusterName,
		}

		err := workflow.ExecuteActivity(ctx, CreateElasticIPActivityName, activityInput).Get(ctx, &eip)
		if err != nil {
			return err
		}

		masterInput.EIPAllocationID = eip.AllocationId
		externalAddress = eip.PublicIp
	}

	// Update cluster network
	{
		activityInput := &UpdateClusterNetworkActivityInput{
			ClusterID:       input.ClusterID,
			APISeverAddress: externalAddress,
			VPCID:           vpcOutput["VpcId"],
			Subnets:         vpcOutput["SubnetIds"],
		}
		err := workflow.ExecuteActivity(ctx, UpdateClusterNetworkActivityName, activityInput).Get(ctx, nil)
		if err != nil {
			return err
		}
	}

	var masterStackID string
	// Create master
	{
		err := workflow.ExecuteActivity(ctx, CreateMasterActivityName, masterInput).Get(ctx, &masterStackID)
		if err != nil {
			return err
		}
	}

	var masterOutput map[string]string

	// Wait for master
	{
		if masterStackID == "" {
			return errors.New("missing stack ID")
		}

		activityInput := WaitCFCompletionActivityInput{AWSActivityInput: awsActivityInput, StackID: masterStackID}
		err := workflow.ExecuteActivity(ctx, WaitCFCompletionActivityName, activityInput).Get(ctx, &masterOutput)
		if err != nil {
			return err
		}
	}

	signalName := "master-ready"
	signalChan := workflow.GetSignalChannel(ctx, signalName)

	s := workflow.NewSelector(ctx)
	s.AddReceive(signalChan, func(c workflow.Channel, more bool) {
		c.Receive(ctx, nil)
		workflow.GetLogger(ctx).Info("Received signal!", zap.String("signal", signalName))
	})
	s.Select(ctx)

	if len(nodePools) == 1 {
		err := workflow.ExecuteActivity(ctx, SetMasterTaintActivityName, SetMasterTaintActivityInput{
			ClusterID: input.ClusterID,
		}).Get(ctx, nil)
		if err != nil {
			return err
		}
	}

	// Create nodes
	{
		futures := make([]workflow.Future, len(nodePools))

		for i, np := range nodePools {
			if !np.Master {
				subnetID := strings.Split(vpcOutput["SubnetIds"], ",")[0]

				createWorkerPoolActivityInput := CreateWorkerPoolActivityInput{
					ClusterID:                 input.ClusterID,
					Pool:                      np,
					WorkerInstanceProfile:     rolesOutput["WorkerInstanceProfile"],
					VPCID:                     vpcOutput["VpcId"],
					VPCDefaultSecurityGroupID: vpcDefaultSecurityGroupID,
					SubnetID:                  subnetID,
					ClusterSecurityGroup:      masterOutput["ClusterSecurityGroup"],
					ExternalBaseUrl:           input.PipelineExternalURL,
					ExternalBaseUrlInsecure:   input.PipelineExternalURLInsecure,
					SSHKeyName:                keyOut.KeyName,
				}

				futures[i] = workflow.ExecuteActivity(ctx, CreateWorkerPoolActivityName, createWorkerPoolActivityInput)
			}
		}

		errs := make([]error, len(futures))
		for i, future := range futures {
			if future != nil {
				errs[i] = errors.Wrapf(future.Get(ctx, nil), "couldn't create nodepool %q", nodePools[i].Name)
			}
		}

		return errors.Combine(errs...)
	}
}
