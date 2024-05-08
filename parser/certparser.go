package certparser

// >>>>>> COPIED from https://github.com/google/go-tpm-tools/blob/f599e6c6bb64d3c03e9507c9fc12c6dbf4a2f640/server/verify.go#L176

import (
	"crypto/x509"
	"encoding/asn1"

	"fmt"

	pb "github.com/google/go-tpm-tools/proto/attest"
)

var OidExtensionSubjectAltName = []int{2, 5, 29, 17}
var cloudComputeInstanceIdentifierOID asn1.ObjectIdentifier = []int{1, 3, 6, 1, 4, 1, 11129, 2, 1, 21}

type gceSecurityProperties struct {
	SecurityVersion int64 `asn1:"explicit,tag:0,optional"`
	IsProduction    bool  `asn1:"explicit,tag:1,optional"`
}

type gceInstanceInfo struct {
	Zone               string `asn1:"utf8"`
	ProjectNumber      int64
	ProjectID          string `asn1:"utf8"`
	InstanceID         int64
	InstanceName       string                `asn1:"utf8"`
	SecurityProperties gceSecurityProperties `asn1:"explicit,optional"`
}

func GetInstanceInfo(cert *x509.Certificate) (*pb.GCEInstanceInfo, error) {

	extensions := cert.Extensions
	var rawInfo []byte
	for _, ext := range extensions {
		if ext.Id.Equal(cloudComputeInstanceIdentifierOID) {
			rawInfo = ext.Value
			break
		}
	}

	// If GCE Instance Info extension is not found.
	if len(rawInfo) == 0 {
		return nil, nil
	}

	info := gceInstanceInfo{}
	if _, err := asn1.Unmarshal(rawInfo, &info); err != nil {
		return nil, fmt.Errorf("failed to parse GCE Instance Information Extension: %w", err)
	}

	// TODO: Remove when fields are changed to uint64.
	if info.ProjectNumber < 0 || info.InstanceID < 0 || info.SecurityProperties.SecurityVersion < 0 {
		return nil, fmt.Errorf("negative integer fields found in GCE Instance Information Extension")
	}

	// Check production.
	if !info.SecurityProperties.IsProduction {
		return nil, nil
	}

	return &pb.GCEInstanceInfo{
		Zone:          info.Zone,
		ProjectId:     info.ProjectID,
		ProjectNumber: uint64(info.ProjectNumber),
		InstanceName:  info.InstanceName,
		InstanceId:    uint64(info.InstanceID),
	}, nil
}
