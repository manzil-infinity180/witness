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

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/intoto"
	"github.com/in-toto/witness/oci"
	"github.com/in-toto/witness/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeTestEnvelope(t *testing.T, payloadType string, signatures []dsse.Signature, subjectDigest string) dsse.Envelope {
	t.Helper()
	statement := intoto.Statement{
		Type:          intoto.StatementType,
		PredicateType: "https://slsa.dev/provenance/v0.2",
		Subject: []intoto.Subject{
			{Name: "test/image", Digest: map[string]string{"sha256": subjectDigest}},
		},
		Predicate: json.RawMessage(`{"builder":{"id":"test-builder"}}`),
	}
	payload, err := json.Marshal(statement)
	require.NoError(t, err)
	return dsse.Envelope{
		Payload:     payload,
		PayloadType: payloadType,
		Signatures:  signatures,
	}
}

func writeEnvelopeFile(t *testing.T, envelopes ...dsse.Envelope) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "attestation.json")
	file, err := os.Create(path)
	require.NoError(t, err)
	encoder := json.NewEncoder(file)
	for _, env := range envelopes {
		require.NoError(t, encoder.Encode(env))
	}
	require.NoError(t, file.Close())
	return path
}

// startTestRegistry starts an in-memory OCI registry, pushes a random image
// to it, and returns the digest reference of the image along with the remote
// options needed to talk to the registry.
func startTestRegistry(t *testing.T) (name.Digest, []remote.Option) {
	t.Helper()
	server := httptest.NewServer(registry.New())
	t.Cleanup(server.Close)

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	remoteOpts := []remote.Option{remote.WithTransport(server.Client().Transport)}

	img, err := random.Image(1024, 2)
	require.NoError(t, err)
	tag, err := name.NewTag(fmt.Sprintf("%s/test/image:latest", u.Host))
	require.NoError(t, err)
	require.NoError(t, remote.Write(tag, img, remoteOpts...))

	digest, err := img.Digest()
	require.NoError(t, err)
	return tag.Context().Digest(digest.String()), remoteOpts
}

func TestValidateEnvelope(t *testing.T) {
	validSignatures := []dsse.Signature{{KeyID: "test", Signature: []byte("test")}}

	tests := []struct {
		name        string
		payloadType string
		signatures  []dsse.Signature
		wantError   string
	}{
		{
			name:        "valid intoto envelope",
			payloadType: IntotoPayloadType,
			signatures:  validSignatures,
		},
		{
			name:        "invalid payload type",
			payloadType: "invalid/type",
			signatures:  validSignatures,
			wantError:   "invalid payloadType",
		},
		{
			name:        "empty payload type",
			payloadType: "",
			signatures:  validSignatures,
			wantError:   "invalid payloadType",
		},
		{
			name:        "no signatures",
			payloadType: IntotoPayloadType,
			signatures:  []dsse.Signature{},
			wantError:   "could not attach attestation without having signatures",
		},
		{
			name:        "nil signatures",
			payloadType: IntotoPayloadType,
			signatures:  nil,
			wantError:   "could not attach attestation without having signatures",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := makeTestEnvelope(t, tt.payloadType, tt.signatures, "abc123")
			err := validateEnvelope(env)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLoadEnvelopes(t *testing.T) {
	validSignatures := []dsse.Signature{{KeyID: "test", Signature: []byte("test")}}

	t.Run("single envelope", func(t *testing.T) {
		path := writeEnvelopeFile(t, makeTestEnvelope(t, IntotoPayloadType, validSignatures, "abc123"))
		envelopes, err := loadEnvelopes(path)
		require.NoError(t, err)
		assert.Len(t, envelopes, 1)
	})

	t.Run("multiple concatenated envelopes", func(t *testing.T) {
		path := writeEnvelopeFile(t,
			makeTestEnvelope(t, IntotoPayloadType, validSignatures, "abc123"),
			makeTestEnvelope(t, IntotoPayloadType, validSignatures, "def456"),
		)
		envelopes, err := loadEnvelopes(path)
		require.NoError(t, err)
		assert.Len(t, envelopes, 2)
	})

	t.Run("empty file", func(t *testing.T) {
		path := writeEnvelopeFile(t)
		_, err := loadEnvelopes(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no DSSE envelopes")
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := loadEnvelopes(filepath.Join(t.TempDir(), "does-not-exist.json"))
		require.Error(t, err)
	})

	t.Run("malformed json", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "malformed.json")
		require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))
		_, err := loadEnvelopes(path)
		require.Error(t, err)
	})
}

func TestAttestationCmd(t *testing.T) {
	validSignatures := []dsse.Signature{{KeyID: "test", Signature: []byte("test")}}
	const mismatchedDigest = "0000000000000000000000000000000000000000000000000000000000000000"

	tests := []struct {
		name             string
		payloadType      string
		signatures       []dsse.Signature
		subjectDigest    string // empty means "use the image digest"
		skipVerification bool
		wantError        string
	}{
		{
			name:        "valid envelope with matching subject digest",
			payloadType: IntotoPayloadType,
			signatures:  validSignatures,
		},
		{
			name:          "subject digest mismatch",
			payloadType:   IntotoPayloadType,
			signatures:    validSignatures,
			subjectDigest: mismatchedDigest,
			wantError:     "no subject in the attestation matches the image digest",
		},
		{
			name:             "subject digest mismatch with skip verification",
			payloadType:      IntotoPayloadType,
			signatures:       validSignatures,
			subjectDigest:    mismatchedDigest,
			skipVerification: true,
		},
		{
			name:        "invalid payload type",
			payloadType: "invalid/type",
			signatures:  validSignatures,
			wantError:   "invalid payloadType",
		},
		{
			name:        "no signatures",
			payloadType: IntotoPayloadType,
			signatures:  nil,
			wantError:   "could not attach attestation without having signatures",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imageDigest, remoteOpts := startTestRegistry(t)

			subjectDigest := tt.subjectDigest
			if subjectDigest == "" {
				hash, err := v1.NewHash(imageDigest.DigestStr())
				require.NoError(t, err)
				subjectDigest = hash.Hex
			}

			path := writeEnvelopeFile(t, makeTestEnvelope(t, tt.payloadType, tt.signatures, subjectDigest))
			o := &options.AttachAttestationOptions{
				ImageURI:         imageDigest.String(),
				SkipVerification: tt.skipVerification,
				Registry:         oci.RegistryOptions{RegistryClientOpts: remoteOpts},
			}

			err := AttestationCmd(context.Background(), o, []string{path})
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
				return
			}
			require.NoError(t, err)

			// The attestation is discoverable at the expected tag.
			hash, err := v1.NewHash(imageDigest.DigestStr())
			require.NoError(t, err)
			attTag := imageDigest.Context().Tag(fmt.Sprintf("%s-%s.%s", hash.Algorithm, hash.Hex, oci.AttestationTagSuffix))
			written, err := remote.Image(attTag, remoteOpts...)
			require.NoError(t, err)

			manifest, err := written.Manifest()
			require.NoError(t, err)
			require.Len(t, manifest.Layers, 1)
			assert.Equal(t, DssePayloadType, string(manifest.Layers[0].MediaType))
		})
	}
}

func TestAttestationCmdMultipleAttestations(t *testing.T) {
	validSignatures := []dsse.Signature{{KeyID: "test", Signature: []byte("test")}}
	imageDigest, remoteOpts := startTestRegistry(t)

	hash, err := v1.NewHash(imageDigest.DigestStr())
	require.NoError(t, err)

	first := writeEnvelopeFile(t, makeTestEnvelope(t, IntotoPayloadType, validSignatures, hash.Hex))
	second := writeEnvelopeFile(t,
		makeTestEnvelope(t, IntotoPayloadType, validSignatures, hash.Hex),
		makeTestEnvelope(t, IntotoPayloadType, validSignatures, hash.Hex),
	)

	o := &options.AttachAttestationOptions{
		ImageURI: imageDigest.String(),
		Registry: oci.RegistryOptions{RegistryClientOpts: remoteOpts},
	}
	require.NoError(t, AttestationCmd(context.Background(), o, []string{first, second}))

	attTag := imageDigest.Context().Tag(fmt.Sprintf("%s-%s.%s", hash.Algorithm, hash.Hex, oci.AttestationTagSuffix))
	written, err := remote.Image(attTag, remoteOpts...)
	require.NoError(t, err)

	manifest, err := written.Manifest()
	require.NoError(t, err)
	assert.Len(t, manifest.Layers, 3)
}
