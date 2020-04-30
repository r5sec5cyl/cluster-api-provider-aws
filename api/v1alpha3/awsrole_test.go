package v1alpha3

import "testing"

func TestExample(t *testing.T) {
	tests := []struct{
		provider AWSIdentityTypeProvider
	}{
		{
			&AWSRoleIdentity{
				AWSRole:                  AWSRole{},
				ExternalID:               "",
				Tags:                     nil,
				TransitiveTags:           nil,
				SourceIdentitySecretName: "",
			},
		},
	}
	for _, test := range tests {
		hash, err := test.provider.Hash()
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(hash) <=0 {
			t.Errorf("expected hash, got %v", hash)
		}
	}
}
