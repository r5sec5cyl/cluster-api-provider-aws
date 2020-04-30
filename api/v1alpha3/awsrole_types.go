package v1alpha3

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/service/sts"
	"time"
)

type AWSRole struct {
	// The Amazon Resource Name (ARN) of the role to assume.
	// +kubebuilder:validation:Pattern:=[\u0009\u000A\u000D\u0020-\u007E\u0085\u00A0-\uD7FF\uE000-\uFFFD\u10000-\u10FFFF]+
	RoleArn string `json:"roleARN"`
	// An identifier for the assumed role session
	// +kubebuilder:validation:Pattern:=[\w+=,.@-]*
	SessionName string `json:"sessionName,omitempty"`
	// The duration, in seconds, of the role session before it is renewed.
	// +kubebuilder:validation:Minimum:=900
	// +kubebuilder:validation:Maximum:=43200
	DurationSeconds uint `json:"durationSeconds,omitempty"`
	// An IAM policy in JSON format that you want to use as an inline session policy.
	// +kubebuilder:validation:Pattern:=[\u0009\u000A\u000D\u0020-\u00FF]+
	InlinePolicy string `json:"inlinePolicy,omitempty"`
	// The Amazon Resource Names (ARNs) of the IAM managed policies that you want to use as managed session policies.
	// The policies must exist in the same account as the role.
	PolicyARNs []string `json:"policyARNs,omitempty"`
}

type AWSRoleIdentity struct {
	AWSRole

	provider credentials.Provider
	// A unique identifier that might be required when you assume a role in another account.
	// +kubebuilder:validation:Pattern:=[\w+=,.@:\/-]*
	ExternalID string `json:"externalID,omitempty"`
	// A list of session tags that you want to pass.
	// Each session tag consists of a key name and an associated value.
	Tags map[string]string `json:"tags,omitempty"`
	// A list of keys for session tags that you want to set as transitive. If you set a tag key as transitive,
	TransitiveTags []string `json:"transitiveTags,omitempty"`
	// An optional reference to another credential to use to assume role
	SourceIdentitySecretName string `json:"controlPlaneRef,omitempty"`
}

var _ AWSIdentityTypeProvider = &AWSRoleIdentity{}

func (i *AWSRoleIdentity) Hash() (string, error) {
	var roleIdentityValue bytes.Buffer
	err := gob.NewEncoder(&roleIdentityValue).Encode(i)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	return string(hash.Sum(roleIdentityValue.Bytes())), nil
}

func (i *AWSRoleIdentity) IsExpired() bool {
	if i.provider == nil {
		return true
	}
	return i.provider.IsExpired()
}

func (i *AWSRoleIdentity) Retrieve() (credentials.Value, error) {
	if i.provider == nil {
		i.setNewAssumeRoleProvider()
	}
	return i.provider.Retrieve()
}

func (i *AWSRoleIdentity) setNewAssumeRoleProvider() {
	var policyARNs []*sts.PolicyDescriptorType
	for _, policyARN := range i.PolicyARNs {
		policyARNs = append(policyARNs, &sts.PolicyDescriptorType{Arn:&policyARN})
	}
	var tags []*sts.Tag
	for key, value := range i.Tags {
		tags = append(tags, &sts.Tag{
			Key: &key,
			Value: &value,
		})
	}
	var transitiveTags []*string
	for _, tagKey := range i.TransitiveTags {
		transitiveTags = append(transitiveTags, &tagKey)
	}
	i.provider = &stscreds.AssumeRoleProvider{
		RoleARN:           i.RoleArn,
		RoleSessionName:   i.SessionName,
		Tags:              tags,
		TransitiveTagKeys: transitiveTags,
		Duration:          time.Duration(i.DurationSeconds) * time.Second,
		Policy:            aws.String(i.InlinePolicy),
		PolicyArns:        policyARNs,
	}
}
