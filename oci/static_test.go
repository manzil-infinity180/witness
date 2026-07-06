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
	"bytes"
	"encoding/base64"
	"io"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaticLayer(t *testing.T) {
	tests := []struct {
		name            string
		payload         []byte
		b64sig          string
		opts            []StaticOption
		wantMediaType   types.MediaType
		wantAnnotations map[string]string
	}{
		{
			name:          "attestation with default options",
			payload:       []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[]}`),
			b64sig:        "",
			wantMediaType: SimpleSigningMediaType,
			wantAnnotations: map[string]string{
				SignatureAnnotationKey: "",
			},
		},
		{
			name:          "signature with custom media type",
			payload:       []byte("test payload"),
			b64sig:        base64.StdEncoding.EncodeToString([]byte("test signature")),
			opts:          []StaticOption{WithLayerMediaType("application/vnd.dsse.envelope.v1+json")},
			wantMediaType: "application/vnd.dsse.envelope.v1+json",
			wantAnnotations: map[string]string{
				SignatureAnnotationKey: base64.StdEncoding.EncodeToString([]byte("test signature")),
			},
		},
		{
			name:    "signature with custom annotations",
			payload: []byte("annotated payload"),
			b64sig:  base64.StdEncoding.EncodeToString([]byte("sig")),
			opts: []StaticOption{
				WithAnnotations(map[string]string{"org.example/key": "value"}),
			},
			wantMediaType: SimpleSigningMediaType,
			wantAnnotations: map[string]string{
				"org.example/key":      "value",
				SignatureAnnotationKey: base64.StdEncoding.EncodeToString([]byte("sig")),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := NewSignature(tt.payload, tt.b64sig, tt.opts...)
			require.NoError(t, err)

			payload, err := sig.Payload()
			require.NoError(t, err)
			assert.Equal(t, tt.payload, payload)

			b64sig, err := sig.(*staticLayer).Base64Signature()
			require.NoError(t, err)
			assert.Equal(t, tt.b64sig, b64sig)

			rawSig, err := sig.Signature()
			require.NoError(t, err)
			wantRawSig, err := base64.StdEncoding.DecodeString(tt.b64sig)
			require.NoError(t, err)
			assert.Equal(t, wantRawSig, rawSig)

			mt, err := sig.MediaType()
			require.NoError(t, err)
			assert.Equal(t, tt.wantMediaType, mt)

			ann, err := sig.Annotations()
			require.NoError(t, err)
			assert.Equal(t, tt.wantAnnotations, ann)

			size, err := sig.Size()
			require.NoError(t, err)
			assert.Equal(t, int64(len(tt.payload)), size)

			wantHash, _, err := v1.SHA256(bytes.NewReader(tt.payload))
			require.NoError(t, err)

			digest, err := sig.Digest()
			require.NoError(t, err)
			assert.Equal(t, wantHash, digest)

			diffID, err := sig.DiffID()
			require.NoError(t, err)
			assert.Equal(t, wantHash, diffID)

			compressed, err := sig.Compressed()
			require.NoError(t, err)
			compressedBytes, err := io.ReadAll(compressed)
			require.NoError(t, err)
			assert.Equal(t, tt.payload, compressedBytes)

			uncompressed, err := sig.Uncompressed()
			require.NoError(t, err)
			uncompressedBytes, err := io.ReadAll(uncompressed)
			require.NoError(t, err)
			assert.Equal(t, tt.payload, uncompressedBytes)
		})
	}
}

func TestNewAttestation(t *testing.T) {
	payload := []byte("attestation payload")
	att, err := NewAttestation(payload, WithLayerMediaType("application/vnd.dsse.envelope.v1+json"))
	require.NoError(t, err)

	// Attestations carry the signature inside the payload, so the
	// Base64Signature is empty.
	b64sig, err := att.(*staticLayer).Base64Signature()
	require.NoError(t, err)
	assert.Empty(t, b64sig)

	got, err := att.Payload()
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}
