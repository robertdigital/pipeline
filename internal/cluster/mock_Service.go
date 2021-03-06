// Code generated by mockery v1.0.0. DO NOT EDIT.

package cluster

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// MockService is an autogenerated mock type for the Service type
type MockService struct {
	mock.Mock
}

// DeleteCluster provides a mock function with given fields: ctx, clusterIdentifier, options
func (_m *MockService) DeleteCluster(ctx context.Context, clusterIdentifier Identifier, options DeleteClusterOptions) (bool, error) {
	ret := _m.Called(ctx, clusterIdentifier, options)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, Identifier, DeleteClusterOptions) bool); ok {
		r0 = rf(ctx, clusterIdentifier, options)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, Identifier, DeleteClusterOptions) error); ok {
		r1 = rf(ctx, clusterIdentifier, options)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
