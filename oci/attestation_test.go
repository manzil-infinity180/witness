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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAttachAndWriteAttestations pushes an image to an in-memory registry,
// attaches attestations to it, publishes them with WriteAttestations, and
// verifies that the attestation layers land in the expected tag with the
// expected payloads and annotations.
func TestAttachAndWriteAttestations(t *testing.T) {
	server := httptest.NewServer(registry.New())
	defer server.Close()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	remoteOpts := []Option{WithRemoteOptions(remote.WithTransport(server.Client().Transport))}

	// Push a random image to the registry.
	img, err := random.Image(1024, 3)
	require.NoError(t, err)
	tag, err := name.NewTag(fmt.Sprintf("%s/test/image:latest", u.Host))
	require.NoError(t, err)
	require.NoError(t, remote.Write(tag, img, remote.WithTransport(server.Client().Transport)))

	// Fetch it back as a signed entity.
	se, err := SignedEntity(tag, remoteOpts...)
	require.NoError(t, err)
	require.NotNil(t, se)

	// The image has no attestations yet.
	atts, err := se.Attestations()
	require.NoError(t, err)
	existing, err := atts.Get()
	require.NoError(t, err)
	assert.Empty(t, existing)

	// Attach two attestations.
	payloads := [][]byte{[]byte(`{"attestation":"one"}`), []byte(`{"attestation":"two"}`)}
	for _, payload := range payloads {
		att, err := NewAttestation(payload, WithLayerMediaType("application/vnd.dsse.envelope.v1+json"))
		require.NoError(t, err)
		se, err = AttachAttestationToEntity(se, att)
		require.NoError(t, err)
	}

	// The attached attestations are visible on the entity.
	atts, err = se.Attestations()
	require.NoError(t, err)
	attached, err := atts.Get()
	require.NoError(t, err)
	require.Len(t, attached, len(payloads))

	// Publish the attestations.
	require.NoError(t, WriteAttestations(tag.Context(), se, remoteOpts...))

	// The attestations are discoverable at the expected tag.
	digest, err := se.Digest()
	require.NoError(t, err)
	attTag, err := name.NewTag(fmt.Sprintf("%s/test/image:%s-%s.%s", u.Host, digest.Algorithm, digest.Hex, AttestationTagSuffix))
	require.NoError(t, err)

	written, err := remote.Image(attTag, remote.WithTransport(server.Client().Transport))
	require.NoError(t, err)
	manifest, err := written.Manifest()
	require.NoError(t, err)
	require.Len(t, manifest.Layers, len(payloads))

	for i, layerDesc := range manifest.Layers {
		layer, err := written.LayerByDigest(layerDesc.Digest)
		require.NoError(t, err)
		rc, err := layer.Compressed()
		require.NoError(t, err)
		got, err := io.ReadAll(rc)
		require.NoError(t, err)
		require.NoError(t, rc.Close())
		assert.Equal(t, payloads[i], got)
		assert.Contains(t, layerDesc.Annotations, SignatureAnnotationKey)
	}

	// Fetching the entity again shows the attestations from the registry.
	se, err = SignedEntity(tag, remoteOpts...)
	require.NoError(t, err)
	atts, err = se.Attestations()
	require.NoError(t, err)
	fetched, err := atts.Get()
	require.NoError(t, err)
	assert.Len(t, fetched, len(payloads))

	// Attaching and writing again appends to the existing attestations.
	att, err := NewAttestation([]byte(`{"attestation":"three"}`))
	require.NoError(t, err)
	se, err = AttachAttestationToEntity(se, att)
	require.NoError(t, err)
	require.NoError(t, WriteAttestations(tag.Context(), se, remoteOpts...))

	written, err = remote.Image(attTag, remote.WithTransport(server.Client().Transport))
	require.NoError(t, err)
	manifest, err = written.Manifest()
	require.NoError(t, err)
	assert.Len(t, manifest.Layers, len(payloads)+1)
}

// TestWriteAttestationsTagNaming verifies the attestations are published to
// the cosign-compatible sha256-<hex>.att tag.
func TestWriteAttestationsTagNaming(t *testing.T) {
	originalRemoteWrite := remoteWrite
	originalDefaultOptionsFunc := defaultOptionsFunc
	t.Cleanup(func() {
		remoteWrite = originalRemoteWrite
		defaultOptionsFunc = originalDefaultOptionsFunc
	})

	// Answer the existing-attestations lookup with a 404 so the test never
	// needs network access or credentials.
	defaultOptionsFunc = func() []remote.Option {
		return []remote.Option{remote.WithTransport(&notFoundRoundTripper{})}
	}

	img, err := random.Image(300, 2)
	require.NoError(t, err)
	si := Image(img)

	want := 3
	for i := range want {
		att, err := NewAttestation(fmt.Appendf(nil, "%d", i))
		require.NoError(t, err)
		si, err = AttachAttestationToImage(si, att)
		require.NoError(t, err)
	}

	var capturedTag name.Reference
	var capturedLayers int
	remoteWrite = func(tag name.Reference, img v1.Image, opts ...remote.Option) error {
		capturedTag = tag
		layers, err := img.Layers()
		if err != nil {
			return err
		}
		capturedLayers = len(layers)
		return nil
	}

	ref := name.MustParseReference("registry.example.com/test:latest")
	require.NoError(t, WriteAttestations(ref.Context(), si))

	digest, err := img.Digest()
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("registry.example.com/test:%s-%s.att", digest.Algorithm, digest.Hex), capturedTag.String())
	assert.Equal(t, want, capturedLayers)
}

// notFoundRoundTripper responds to every request with a 404 so lookups of
// existing attestation tags resolve to "not found" without network access.
type notFoundRoundTripper struct{}

func (n *notFoundRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Status:     "404 Not Found",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`)),
		Request:    req,
	}, nil
}
