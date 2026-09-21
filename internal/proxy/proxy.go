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

// supportedSchemes are the proxy schemes net/http can actually dial. httpproxy
// silently reinterprets anything else as a plain HTTP proxy, so an unsupported
// scheme has to be rejected here or it fails later as a protocol error.
var supportedSchemes = map[string]struct{}{
	"http":    {},
	"https":   {},
	"socks5":  {},
	"socks5h": {},
}

// proxyEnvVars are the spellings a child process may read. Both cases are
// listed because curl deliberately ignores the upper-case HTTP_PROXY for
// plain-http URLs, and other tools only look at one or the other.
var proxyEnvVars = []string{
	"HTTP_PROXY", "http_proxy",
	"HTTPS_PROXY", "https_proxy",
}

// Apply routes outbound requests through proxyURL by replacing the proxy
// resolution on http.DefaultTransport. A blank proxyURL changes nothing, so the
// environment variables keep working on their own.
//
// An explicit proxy overrides HTTP_PROXY / HTTPS_PROXY, on the grounds that the
// user just named one. NO_PROXY is still honoured, so internal hosts can be
// exempted as usual.
//
// Must run after tls.Apply: this clones the transport that call installed, so
// the CA bundle and skip-verify settings are carried over rather than dropped.
func Apply(proxyURL string) error {
	if proxyURL == "" {
		return nil
	}

	if err := Validate(proxyURL); err != nil {
		return err
	}

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return errors.New("http.DefaultTransport is not *http.Transport")
	}

	// FromEnvironment picks up NO_PROXY; overriding both proxy fields leaves
	// the exemption list intact while making this value the one that is used.
	config := httpproxy.FromEnvironment()
	config.HTTPProxy = proxyURL
	config.HTTPSProxy = proxyURL

	proxyFunc := config.ProxyFunc()

	transport := base.Clone()
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		return proxyFunc(req.URL)
	}

	http.DefaultTransport = transport

	return nil
}

// PropagateEnv exports proxyURL as HTTP_PROXY / HTTPS_PROXY (both cases) so
// plugin subprocesses traverse the same proxy as the CLI itself. Call after
// Apply.
//
// It overwrites any value already in the environment, matching Apply: leaving a
// stale variable in place would put the CLI and its plugins on different
// proxies, which is harder to diagnose than either one being wrong.
//
// Note that this puts the value — credentials included, if the URL carries any
// — into the environment of every subprocess the CLI spawns, where it is
// readable through /proc on Linux. A proxy that needs a password is better
// configured without one in the URL where the network allows it.
func PropagateEnv(proxyURL string) error {
	if proxyURL == "" {
		return nil
	}

	for _, name := range proxyEnvVars {
		if err := os.Setenv(name, proxyURL); err != nil {
			return fmt.Errorf("set %s: %w", name, err)
		}
	}

	return nil
}

// Validate reports whether proxyURL is usable as a forward proxy.
//
// httpproxy never errors on a malformed value: it either builds a nonsense URL
// or quietly resolves to no proxy, sending the request out direct. Both would
// surface far from the cause, and "direct" is the one outcome a user setting
// --proxy definitely does not want.
func Validate(proxyURL string) error {
	raw := proxyURL

	// A bare host:port is accepted and assumed http, matching httpproxy and the
	// form most corporate handbooks hand out.
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid proxy %q: not a URL", Redact(proxyURL))
	}

	if parsed.Host == "" {
		return fmt.Errorf("invalid proxy %q: expected a URL like http://host:port", Redact(proxyURL))
	}

	// A forward proxy is a host and a port, never a path. Catching this rejects
	// a missing colon after the scheme ("http//proxy:8080"), which otherwise
	// parses to the host "http" and silently dials the wrong place.
	if parsed.Path != "" && parsed.Path != "/" {
		return fmt.Errorf("invalid proxy %q: expected a URL like http://host:port", Redact(proxyURL))
	}

	if _, ok := supportedSchemes[parsed.Scheme]; !ok {
		return fmt.Errorf(
			"invalid proxy %q: scheme %q is not supported (use http, https, socks5 or socks5h)",
			Redact(proxyURL), parsed.Scheme,
		)
	}

	return nil
}

// Redact returns proxyURL with any password masked, for printing. It falls back
// to a fixed placeholder rather than the original when the value cannot be
// parsed, so an unparseable URL can never leak a password through an error
// message.
func Redact(proxyURL string) string {
	if proxyURL == "" {
		return ""
	}

	raw := proxyURL
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		if strings.Contains(proxyURL, "@") {
			return "(proxy URL with credentials)"
		}

		return proxyURL
	}

	if parsed.User == nil {
		return proxyURL
	}

	return parsed.Redacted()
}
