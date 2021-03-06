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

package clusterdriver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/banzaicloud/pipeline/internal/cluster"
)

func TestMakeClusterEndpoints_DeleteCluster(t *testing.T) {
	const clusterID = uint(1)
	const clusterName = "my-cluster"
	const orgID = uint(1)

	testCases := map[string]struct {
		identifier cluster.Identifier
		options    cluster.DeleteClusterOptions
		request    deleteClusterRequest
	}{
		"id identifier": {
			identifier: cluster.Identifier{
				ClusterID: clusterID,
			},
			options: cluster.DeleteClusterOptions{
				Force: true,
			},
			request: deleteClusterRequest{
				ClusterID: clusterID,
				Force:     true,
			},
		},
		"name identifier": {
			identifier: cluster.Identifier{
				OrganizationID: orgID,
				ClusterName:    clusterName,
			},
			options: cluster.DeleteClusterOptions{
				Force: true,
			},
			request: deleteClusterRequest{
				OrganizationID: orgID,
				ClusterName:    clusterName,
				Force:          true,
			},
		},
	}

	for name, testCase := range testCases {
		testCase := testCase

		t.Run(name, func(t *testing.T) {
			service := new(cluster.MockService)
			service.On("DeleteCluster", mock.Anything, testCase.identifier, testCase.options).Return(false, nil)

			e := MakeClusterEndpoints(service).DeleteCluster

			_, err := e(context.Background(), testCase.request)
			require.NoError(t, err)

			service.AssertExpectations(t)
		})
	}
}
