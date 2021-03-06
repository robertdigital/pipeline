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

type BackupBucketResponse struct {

	Id int32 `json:"id,omitempty"`

	Name string `json:"name,omitempty"`

	Cloud string `json:"cloud,omitempty"`

	SecretId string `json:"secretId,omitempty"`

	Status string `json:"status,omitempty"`

	InUse bool `json:"inUse,omitempty"`
}
