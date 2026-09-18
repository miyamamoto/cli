// Copyright 2026 DataRobot, Inc. and its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package proxy routes the CLI's outbound HTTP traffic through an explicitly
// configured forward proxy.
//
// Go only ever reads HTTP_PROXY / HTTPS_PROXY / NO_PROXY; it does not consult
// the operating system's proxy settings on any platform. Users on networks
// that require a proxy therefore need somewhere to state it, which is what the
// --proxy flag and the matching drconfig.yaml value provide — the same shape
// gcloud, docker, npm and git all use.
package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/http/httpproxy"
)

// Apply routes outbound requests through proxyURL by replacing the proxy
// resolution on http.DefaultTransport. A blank proxyURL changes nothing, so the
// environment variables keep working on their own.
//
// NO_PROXY is still honoured, so an explicit proxy can be combined with the
// usual exemptions for internal hosts.
//
// Must run after tls.Apply: this clones the transport that call installed, so
// the CA bundle and skip-verify settings are carried over rather than dropped.
func Apply(proxyURL string) error {
	if proxyURL == "" {
		return nil
	}

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return errors.New("http.DefaultTransport is not *http.Transport")
	}

	if err := validate(proxyURL); err != nil {
		return err
	}

	config := httpproxy.FromEnvironment()
	config.HTTPProxy = proxyURL
	config.HTTPSProxy = proxyURL

	proxyFunc := config.ProxyFunc()

	// httpproxy reports a value it cannot use by returning no proxy at all, so
	// resolve once here rather than letting the request go out direct — the
	// whole point of setting --proxy is that direct is not an option.
	sample, err := proxyFunc(&url.URL{Scheme: "https", Host: "example.invalid"})
	if err != nil || sample == nil {
		return fmt.Errorf("invalid proxy %q: expected a URL like http://host:port", proxyURL)
	}

	transport := base.Clone()
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		return proxyFunc(req.URL)
	}

	http.DefaultTransport = transport

	return nil
}

// validate rejects a proxy value before it is installed. httpproxy itself never
// errors on a malformed value: it either builds a nonsense URL or quietly
// resolves to no proxy, both of which would surface far from the cause.
func validate(proxyURL string) error {
	raw := proxyURL

	// A bare host:port is accepted (and assumed http), matching httpproxy.
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid proxy %q: %w", proxyURL, err)
	}

	if parsed.Host == "" {
		return fmt.Errorf("invalid proxy %q: expected a URL like http://host:port", proxyURL)
	}

	return nil
}

// PropagateEnv exports proxyURL as HTTP_PROXY / HTTPS_PROXY so plugin
// subprocesses traverse the same proxy as the CLI itself. Call after Apply.
//
// Values already present in the environment win: the user set those
// deliberately, and overwriting them would change how every child process
// reaches the network.
func PropagateEnv(proxyURL string) error {
	if proxyURL == "" {
		return nil
	}

	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY"} {
		if os.Getenv(name) != "" || os.Getenv(lower(name)) != "" {
			continue
		}

		if err := os.Setenv(name, proxyURL); err != nil {
			return fmt.Errorf("set %s: %w", name, err)
		}
	}

	return nil
}

// lower returns the lower-case spelling of a proxy variable name, which is just
// as widely honoured as the upper-case one.
func lower(name string) string {
	out := []byte(name)
	for i := range out {
		if out[i] >= 'A' && out[i] <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}

	return string(out)
}
