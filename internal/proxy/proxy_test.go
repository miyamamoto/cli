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

package proxy

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const corpProxy = "http://proxy.corp.example:8080"

// clearProxyEnv unsets every spelling httpproxy reads. Clearing only the
// upper-case names leaves a developer's or CI's lower-case no_proxy in force,
// which silently changes what these tests measure.
func clearProxyEnv(t *testing.T) {
	t.Helper()

	for _, name := range []string{
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
		"NO_PROXY", "no_proxy",
	} {
		t.Setenv(name, "")
	}
}

// restoreDefaultTransport returns the current default transport and puts it
// back afterwards, since Apply replaces it process-wide.
func restoreDefaultTransport(t *testing.T) *http.Transport {
	t.Helper()

	original := http.DefaultTransport

	t.Cleanup(func() { http.DefaultTransport = original })

	base, ok := original.(*http.Transport)
	require.True(t, ok)

	return base
}

// resolve asks the installed transport which proxy it would use for rawURL.
func resolve(t *testing.T, rawURL string) *url.URL {
	t.Helper()

	transport, ok := http.DefaultTransport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport.Proxy)

	target, err := url.Parse(rawURL)
	require.NoError(t, err)

	proxyURL, err := transport.Proxy(&http.Request{URL: target})
	require.NoError(t, err)

	return proxyURL
}

func TestApplyBlankProxyLeavesTransportAlone(t *testing.T) {
	original := http.DefaultTransport

	t.Cleanup(func() { http.DefaultTransport = original })

	require.NoError(t, Apply(""))
	assert.Same(t, original, http.DefaultTransport,
		"an unset proxy must leave the environment behaviour untouched")
}

func TestApplyRoutesBothSchemesThroughTheProxy(t *testing.T) {
	clearProxyEnv(t)
	restoreDefaultTransport(t)

	require.NoError(t, Apply(corpProxy))

	for _, target := range []string{"https://app.datarobot.com/api/v2", "http://cli.datarobot.com/x"} {
		resolved := resolve(t, target)
		require.NotNil(t, resolved, "%s should be proxied", target)
		assert.Equal(t, "proxy.corp.example:8080", resolved.Host)
	}
}

func TestApplyStillHonoursNoProxy(t *testing.T) {
	clearProxyEnv(t)
	restoreDefaultTransport(t)
	t.Setenv("NO_PROXY", "internal.example.com")

	require.NoError(t, Apply(corpProxy))

	assert.Nil(t, resolve(t, "https://internal.example.com/x"),
		"NO_PROXY must still carve out internal hosts")
	assert.NotNil(t, resolve(t, "https://app.datarobot.com/x"))
}

// NO_PROXY=* is the documented way to disable proxying globally and is common
// in corporate shells and CI images. An earlier version probed a single host to
// decide whether the value was usable, so this made every command fail with
// "invalid proxy" — naming a URL that was perfectly fine.
func TestApplyAcceptsAProxyEvenWhenNoProxyExemptsEverything(t *testing.T) {
	for _, spelling := range []string{"NO_PROXY", "no_proxy"} {
		t.Run(spelling, func(t *testing.T) {
			clearProxyEnv(t)
			restoreDefaultTransport(t)
			t.Setenv(spelling, "*")

			require.NoError(t, Apply(corpProxy),
				"a blanket NO_PROXY is an exemption, not a malformed proxy")
			assert.Nil(t, resolve(t, "https://app.datarobot.com/x"))
		})
	}
}

func TestApplyOverridesTheProxyEnvironment(t *testing.T) {
	clearProxyEnv(t)
	restoreDefaultTransport(t)
	t.Setenv("HTTPS_PROXY", "http://stale.example:3128")

	require.NoError(t, Apply(corpProxy))

	assert.Equal(t, "proxy.corp.example:8080", resolve(t, "https://app.datarobot.com/x").Host,
		"an explicit --proxy should win over the environment")
}

func TestApplyKeepsTLSSettings(t *testing.T) {
	clearProxyEnv(t)

	base := restoreDefaultTransport(t)

	// Stand in for tls.Apply having installed --ca-cert / -k before us.
	configured := base.Clone()
	configured.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // mirrors tls.Apply(--skip-certificate-check)
	http.DefaultTransport = configured

	require.NoError(t, Apply(corpProxy))

	transport, ok := http.DefaultTransport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport.TLSClientConfig)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify,
		"a TLS-intercepting proxy needs both settings to survive together")
}

func TestApplyAcceptsABareHostAndPort(t *testing.T) {
	clearProxyEnv(t)
	restoreDefaultTransport(t)

	require.NoError(t, Apply("proxy.corp.example:8080"),
		"a bare host:port is what most corporate docs hand out")
	assert.Equal(t, "proxy.corp.example:8080", resolve(t, "https://app.datarobot.com/x").Host)
}

func TestValidateRejectsUnusableValues(t *testing.T) {
	// httpproxy reports none of these: it builds a nonsense URL, or resolves to
	// no proxy and lets the request go out direct.
	cases := map[string]string{
		"not a URL":            "://not a proxy",
		"spaces in host":       "not a proxy",
		"bad percent-encoding": "%%%",
		"missing colon":        "http//proxy.corp:8080",
	}

	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, Validate(value), "%q should be rejected", value)
		})
	}
}

// socks4 is a plausible thing to type and httpproxy quietly treats it as a
// plain HTTP proxy, which fails later as a confusing protocol error.
func TestValidateRejectsUnsupportedSchemes(t *testing.T) {
	for _, value := range []string{"socks4://proxy.corp:1080", "ftp://proxy.corp:8080", "tcp://proxy.corp:8080"} {
		t.Run(value, func(t *testing.T) {
			err := Validate(value)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "not supported")
		})
	}
}

func TestValidateAcceptsTheSupportedSchemes(t *testing.T) {
	for _, value := range []string{
		"http://proxy.corp:8080",
		"https://proxy.corp:8443",
		"socks5://proxy.corp:1080",
		"socks5h://proxy.corp:1080",
		"proxy.corp:8080",
	} {
		t.Run(value, func(t *testing.T) {
			assert.NoError(t, Validate(value))
		})
	}
}

// The value reaches the user through `dr self config`, `dr --debug`, and any
// error naming it — all of which end up pasted into bug reports.
func TestRedactMasksThePassword(t *testing.T) {
	assert.Equal(t, "http://user:xxxxx@proxy.corp:8080",
		Redact("http://user:S3cretP%40ss@proxy.corp:8080"))
}

func TestRedactLeavesAValueWithoutCredentialsReadable(t *testing.T) {
	assert.Equal(t, corpProxy, Redact(corpProxy),
		"the host is what makes a proxy problem diagnosable")
	assert.Equal(t, "proxy.corp:8080", Redact("proxy.corp:8080"))
	assert.Empty(t, Redact(""))
}

func TestRedactNeverLeaksFromAnUnparseableValue(t *testing.T) {
	out := Redact("://user:hunter2@nope")

	assert.NotContains(t, out, "hunter2",
		"a value too broken to parse must not fall through in the clear")
}

func TestApplyErrorsDoNotLeakThePassword(t *testing.T) {
	clearProxyEnv(t)
	restoreDefaultTransport(t)

	err := Apply("socks4://user:hunter2@proxy.corp:1080")

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "hunter2")
}

func TestPropagateEnvExportsBothSpellingsForPlugins(t *testing.T) {
	clearProxyEnv(t)

	require.NoError(t, PropagateEnv(corpProxy))

	// curl ignores the upper-case HTTP_PROXY for plain-http URLs, so a plugin
	// shelling out to it would otherwise miss the proxy entirely.
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		assert.Equal(t, corpProxy, os.Getenv(name), "%s should be exported", name)
	}
}

// Apply overrides the environment for the CLI itself; PropagateEnv has to do
// the same for its children, or the two end up on different proxies.
func TestPropagateEnvOverridesAStaleEnvironment(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "http://stale.example:3128")

	require.NoError(t, PropagateEnv(corpProxy))

	assert.Equal(t, corpProxy, os.Getenv("HTTPS_PROXY"))
}

func TestPropagateEnvBlankProxyChangesNothing(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "http://chosen.example:3128")

	require.NoError(t, PropagateEnv(""))

	assert.Equal(t, "http://chosen.example:3128", os.Getenv("HTTPS_PROXY"))
}
