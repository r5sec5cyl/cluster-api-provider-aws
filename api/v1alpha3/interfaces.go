package v1alpha3

import (
	"github.com/aws/aws-sdk-go/aws/credentials"
)

type AWSIdentityTypeProvider interface {
	credentials.Provider
	// Hash returns a unique hash of the data forming the credentials
	// for this identity
	Hash() (string, error)
}

