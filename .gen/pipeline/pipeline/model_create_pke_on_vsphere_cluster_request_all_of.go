/*
 * Pipeline API
 *
 * Pipeline is a feature rich application platform, built for containers on top of Kubernetes to automate the DevOps experience, continuous application development and the lifecycle of deployments. 
 *
 * API version: latest
 * Contact: info@banzaicloud.com
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package pipeline

type CreatePkeOnVsphereClusterRequestAllOf struct {

	// Folder to create nodes in.
	Folder string `json:"folder,omitempty"`

	// Name of datastore or datastore cluster to place VM disks on.
	Datastore string `json:"datastore,omitempty"`

	// Virtual machines will be created in this resource pool.
	ResourcePool string `json:"resourcePool,omitempty"`

	Nodepools []PkeOnVsphereNodePool `json:"nodepools,omitempty"`
}
