// Copyright 2025 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This file is adapted from the sigstore/cosign project
// (https://github.com/sigstore/cosign) and modified for use in Witness.

package oci

import (
	"encoding/json"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/intoto"
)

// VerifyEnvelopeSubject verifies that the in-toto statement wrapped in the
// provided DSSE envelope has at least one subject whose digest matches the
// digest of the image the attestation is being attached to. This guards
// against accidentally attaching an attestation that describes a different
// artifact.
func VerifyEnvelopeSubject(env dsse.Envelope, imageDigest v1.Hash) error {
	statement := intoto.Statement{}
	if err := json.Unmarshal(env.Payload, &statement); err != nil {
		return fmt.Errorf("unmarshaling in-toto statement from envelope payload: %w", err)
	}

	for _, subject := range statement.Subject {
		digest, ok := subject.Digest[imageDigest.Algorithm]
		if !ok {
			continue
		}
		if digest == imageDigest.Hex {
			return nil
		}
	}

	return fmt.Errorf("no subject in the attestation matches the image digest %s. Use --skip-verification to attach the attestation anyway", imageDigest.String())
}
