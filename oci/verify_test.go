// Copyright 2025 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oci

import (
	"encoding/json"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/intoto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testDigestHex = "6c6fd6a4115c6e998ff357cd914680931bb9a6c1a7cd5f5cb2f5e1c0932ab6ed"

func makeEnvelope(t *testing.T, subjects []intoto.Subject) dsse.Envelope {
	t.Helper()
	statement := intoto.Statement{
		Type:          intoto.StatementType,
		PredicateType: "https://slsa.dev/provenance/v0.2",
		Subject:       subjects,
		Predicate:     json.RawMessage(`{}`),
	}
	payload, err := json.Marshal(statement)
	require.NoError(t, err)
	return dsse.Envelope{
		Payload:     payload,
		PayloadType: "application/vnd.in-toto+json",
		Signatures:  []dsse.Signature{{KeyID: "test", Signature: []byte("test")}},
	}
}

func TestVerifyEnvelopeSubject(t *testing.T) {
	imageDigest := v1.Hash{Algorithm: "sha256", Hex: testDigestHex}

	tests := []struct {
		name      string
		env       dsse.Envelope
		wantError bool
	}{
		{
			name: "subject digest matches image digest",
			env: makeEnvelope(t, []intoto.Subject{
				{Name: "registry.local:5000/knative/demo", Digest: map[string]string{"sha256": testDigestHex}},
			}),
		},
		{
			name: "one of multiple subjects matches",
			env: makeEnvelope(t, []intoto.Subject{
				{Name: "another/artifact", Digest: map[string]string{"sha256": "0000000000000000000000000000000000000000000000000000000000000000"}},
				{Name: "registry.local:5000/knative/demo", Digest: map[string]string{"sha256": testDigestHex}},
			}),
		},
		{
			name: "subject digest does not match image digest",
			env: makeEnvelope(t, []intoto.Subject{
				{Name: "registry.local:5000/knative/demo", Digest: map[string]string{"sha256": "0000000000000000000000000000000000000000000000000000000000000000"}},
			}),
			wantError: true,
		},
		{
			name: "subject missing digest for the image digest algorithm",
			env: makeEnvelope(t, []intoto.Subject{
				{Name: "registry.local:5000/knative/demo", Digest: map[string]string{"sha512": testDigestHex}},
			}),
			wantError: true,
		},
		{
			name:      "no subjects",
			env:       makeEnvelope(t, nil),
			wantError: true,
		},
		{
			name:      "payload is not an in-toto statement",
			env:       dsse.Envelope{Payload: []byte("not json")},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyEnvelopeSubject(tt.env, imageDigest)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
