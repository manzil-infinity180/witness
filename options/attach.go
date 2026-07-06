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

package options

import (
	"github.com/in-toto/witness/oci"
	"github.com/spf13/cobra"
)

// AttachAttestationOptions is the top level wrapper for the attach attestation command.
type AttachAttestationOptions struct {
	ImageURI         string
	SkipVerification bool
	Registry         oci.RegistryOptions
}

var _ Interface = &AttachAttestationOptions{}

// AddFlags implements Interface
func (o *AttachAttestationOptions) AddFlags(cmd *cobra.Command) {
	o.Registry.AddFlags(cmd)

	cmd.Flags().StringVarP(&o.ImageURI, "image-uri", "i", "",
		"OCI image reference to attach the attestation(s) to (required)")

	cmd.Flags().BoolVar(&o.SkipVerification, "skip-verification", false,
		"Skip verification of attestation subjects against the image digest. Do not use this for anything but testing")

	if err := cmd.MarkFlagRequired("image-uri"); err != nil {
		panic(err)
	}
}
