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

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/witness/oci"
	"github.com/in-toto/witness/options"
	"github.com/spf13/cobra"
)

const (
	DssePayloadType   = "application/vnd.dsse.envelope.v1+json"
	IntotoPayloadType = "application/vnd.in-toto+json"
)

func AttachCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attach",
		Short: "Provides utilities for attaching artifacts to other artifacts in a registry",
	}

	cmd.AddCommand(
		attachAttestationCmd(),
	)

	return cmd
}

func attachAttestationCmd() *cobra.Command {
	o := &options.AttachAttestationOptions{}
	cmd := &cobra.Command{
		Use:   "attestation [attestation-file]...",
		Short: "Attach one or more DSSE-wrapped in-toto attestations to a container image in an OCI registry",
		Example: `  # attach a single attestation to a container image
  witness attach attestation attestation.json --image-uri registry.example.com/repo/image:tag

  # attach multiple attestations to a container image
  witness attach attestation first.json second.json --image-uri registry.example.com/repo/image@sha256:...`,
		Args:              cobra.MinimumNArgs(1),
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return AttestationCmd(cmd.Context(), o, args)
		},
	}
	o.AddFlags(cmd)
	return cmd
}

// AttestationCmd attaches the attestations in the provided files to the image
// referenced by o.ImageURI.
func AttestationCmd(ctx context.Context, o *options.AttachAttestationOptions, attestationPaths []string) error {
	remoteOpts, err := o.Registry.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("constructing client options: %w", err)
	}

	ref, err := name.ParseReference(o.ImageURI, o.Registry.NameOptions()...)
	if err != nil {
		return fmt.Errorf("parsing image reference %s: %w", o.ImageURI, err)
	}
	if _, ok := ref.(name.Digest); !ok {
		log.Warnf("image reference %s uses a tag, not a digest, to identify the image to attach to. This can lead you to attach the attestation(s) to a different image than the intended one.", o.ImageURI)
	}

	// Resolve the reference to a digest to avoid a race where a tag is used
	// multiple times, and it potentially points to different things at each access.
	digest, err := oci.ResolveDigest(ref, remoteOpts...)
	if err != nil {
		return fmt.Errorf("resolving digest for %s: %w", o.ImageURI, err)
	}

	digestHash, err := v1.NewHash(digest.DigestStr())
	if err != nil {
		return fmt.Errorf("parsing digest %s: %w", digest.DigestStr(), err)
	}

	se, err := oci.SignedEntity(digest, remoteOpts...)
	if err != nil {
		return fmt.Errorf("fetching signed entity for %s: %w", digest.String(), err)
	}

	if o.SkipVerification {
		log.Warnf("skipping verification of attestation subjects against the image digest")
	}

	attached := 0
	for _, path := range attestationPaths {
		envelopes, err := loadEnvelopes(path)
		if err != nil {
			return fmt.Errorf("loading attestations from %s: %w", path, err)
		}

		for _, env := range envelopes {
			if err := validateEnvelope(env); err != nil {
				return fmt.Errorf("validating attestation from %s: %w", path, err)
			}

			if !o.SkipVerification {
				if err := oci.VerifyEnvelopeSubject(env, digestHash); err != nil {
					return fmt.Errorf("verifying attestation from %s against %s: %w", path, digest.String(), err)
				}
			}

			payload, err := json.Marshal(env)
			if err != nil {
				return fmt.Errorf("marshaling attestation from %s: %w", path, err)
			}

			att, err := oci.NewAttestation(payload, oci.WithLayerMediaType(DssePayloadType))
			if err != nil {
				return fmt.Errorf("creating attestation layer: %w", err)
			}

			se, err = oci.AttachAttestationToEntity(se, att)
			if err != nil {
				return fmt.Errorf("attaching attestation from %s: %w", path, err)
			}
			attached++
		}
	}

	log.Infof("Writing %d attestation(s) to repository %s", attached, digest.Repository.String())
	if err := oci.WriteAttestations(digest.Repository, se, remoteOpts...); err != nil {
		return fmt.Errorf("writing attestations: %w", err)
	}
	return nil
}

// loadEnvelopes reads one or more DSSE envelopes from the file at the given
// path. Multiple envelopes may be concatenated in a single file.
func loadEnvelopes(path string) ([]dsse.Envelope, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Errorf("failed to close attestation file: %v", err)
		}
	}()

	envelopes := []dsse.Envelope{}
	decoder := json.NewDecoder(file)
	for decoder.More() {
		env := dsse.Envelope{}
		if err := decoder.Decode(&env); err != nil {
			return nil, err
		}
		envelopes = append(envelopes, env)
	}
	if len(envelopes) == 0 {
		return nil, fmt.Errorf("no DSSE envelopes found in file")
	}
	return envelopes, nil
}

// validateEnvelope checks that the DSSE envelope wraps an in-toto statement
// and has been signed.
func validateEnvelope(env dsse.Envelope) error {
	if env.PayloadType != IntotoPayloadType {
		return fmt.Errorf("invalid payloadType %s on envelope. Expected %s", env.PayloadType, IntotoPayloadType)
	}
	if len(env.Signatures) == 0 {
		return fmt.Errorf("could not attach attestation without having signatures")
	}
	return nil
}
