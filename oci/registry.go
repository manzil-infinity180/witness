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
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"runtime"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/cobra"
)

// Keychain is an alias of authn.Keychain to expose this configuration option to consumers of this lib
type Keychain = authn.Keychain

// uaString is the User-Agent which `witness` sends with HTTP requests to registries.
var uaString = fmt.Sprintf("witness (%s; %s)", runtime.GOOS, runtime.GOARCH)

// UserAgent returns the User-Agent string which `witness` should send with HTTP requests.
func UserAgent() string {
	return uaString
}

// RegistryOptions is the wrapper for the registry options.
type RegistryOptions struct {
	AllowInsecure     bool
	AllowHTTPRegistry bool
	Keychain          Keychain
	AuthConfig        authn.AuthConfig
	// RegistryClientOpts allows overriding the result of GetRegistryClientOpts.
	RegistryClientOpts []remote.Option
}

func (o *RegistryOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.AuthConfig.Username, "registry-username", "",
		"Registry basic auth username")

	cmd.Flags().StringVar(&o.AuthConfig.Password, "registry-password", "",
		"Registry basic auth password")

	cmd.Flags().StringVar(&o.AuthConfig.RegistryToken, "registry-token", "",
		"Registry bearer auth token")

	cmd.Flags().BoolVar(&o.AllowInsecure, "allow-insecure-registry", false,
		"Allow skipping TLS verification when connecting to the registry. Do not use this for anything but testing")

	cmd.Flags().BoolVar(&o.AllowHTTPRegistry, "allow-http-registry", false,
		"Allow connecting to registries over plain HTTP. Do not use this for anything but testing")
}

func (o *RegistryOptions) NameOptions() []name.Option {
	var nameOpts []name.Option
	if o.AllowHTTPRegistry {
		nameOpts = append(nameOpts, name.Insecure)
	}
	return nameOpts
}

// WithRemoteOptions is a functional option for overriding the default
// remote options passed to GGCR.
func WithRemoteOptions(opts ...remote.Option) Option {
	return func(o *options) {
		o.ROpt = opts
	}
}

func (o *RegistryOptions) ClientOpts(ctx context.Context) ([]Option, error) {
	opts := []Option{WithRemoteOptions(o.GetRegistryClientOpts(ctx)...)}
	targetRepoOverride, err := GetEnvTargetRepository()
	if err != nil {
		return nil, err
	}
	if (targetRepoOverride != name.Repository{}) {
		opts = append(opts, WithTargetRepository(targetRepoOverride))
	}
	return opts, nil
}

// GetRegistryClientOpts returns a set of remote.Option values to configure
// interactions with container registries using go-containerregistry.
func (o *RegistryOptions) GetRegistryClientOpts(ctx context.Context) []remote.Option {
	if o.RegistryClientOpts != nil {
		ropts := o.RegistryClientOpts
		ropts = append(ropts, remote.WithContext(ctx))
		return ropts
	}
	opts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithUserAgent(UserAgent()),
	}

	switch {
	case o.Keychain != nil:
		opts = append(opts, remote.WithAuthFromKeychain(o.Keychain))
	case o.AuthConfig.Username != "" && o.AuthConfig.Password != "":
		opts = append(opts, remote.WithAuth(&authn.Basic{Username: o.AuthConfig.Username, Password: o.AuthConfig.Password}))
	case o.AuthConfig.RegistryToken != "":
		opts = append(opts, remote.WithAuth(&authn.Bearer{Token: o.AuthConfig.RegistryToken}))
	default:
		opts = append(opts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}

	if o.AllowInsecure {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- guarded by the allow-insecure-registry flag
		opts = append(opts, remote.WithTransport(transport))
	}

	// Reuse a remote.Pusher and a remote.Puller for all operations that use these opts.
	// This allows us to avoid re-authenticating for every remote.Function we call,
	// which speeds things up a whole lot.
	pusher, err := remote.NewPusher(opts...)
	if err == nil {
		opts = append(opts, remote.Reuse(pusher))
	}
	puller, err := remote.NewPuller(opts...)
	if err == nil {
		opts = append(opts, remote.Reuse(puller))
	}
	return opts
}

// WithTargetRepository is a functional option for overriding the default
// target repository hosting the signature and attestation tags.
func WithTargetRepository(repo name.Repository) Option {
	return func(o *options) {
		o.TargetRepository = repo
	}
}

// RepoOverrideEnvKey is the environment variable that overrides the
// repository the attestation tags are written to.
const RepoOverrideEnvKey = "WITNESS_REPOSITORY"

// GetEnvTargetRepository returns the Repository specified by
// `os.Getenv(RepoOverrideEnvKey)`, or the empty value if not set.
// Returns an error if the value is set but cannot be parsed.
func GetEnvTargetRepository() (name.Repository, error) {
	if ro := os.Getenv(RepoOverrideEnvKey); ro != "" {
		repo, err := name.NewRepository(ro)
		if err != nil {
			return name.Repository{}, fmt.Errorf("parsing $"+RepoOverrideEnvKey+": %w", err)
		}
		return repo, nil
	}
	return name.Repository{}, nil
}
