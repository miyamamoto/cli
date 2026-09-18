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

// restoreDefaultTransport puts http.DefaultTransport back after a test, since
// Apply replaces it process-wide.
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
	restoreDefaultTransport(t)
	t.Setenv("NO_PROXY", "")

	require.NoError(t, Apply(corpProxy))

	for _, target := range []string{"https://app.datarobot.com/api/v2", "http://cli.datarobot.com/x"} {
		resolved := resolve(t, target)
		require.NotNil(t, resolved, "%s should be proxied", target)
		assert.Equal(t, "proxy.corp.example:8080", resolved.Host)
	}
}

func TestApplyStillHonoursNoProxy(t *testing.T) {
	restoreDefaultTransport(t)
	t.Setenv("NO_PROXY", "internal.example.com")

	require.NoError(t, Apply(corpProxy))

	assert.Nil(t, resolve(t, "https://internal.example.com/x"),
		"NO_PROXY must still carve out internal hosts")
	assert.NotNil(t, resolve(t, "https://app.datarobot.com/x"))
}

func TestApplyOverridesTheProxyEnvironment(t *testing.T) {
	restoreDefaultTransport(t)
	t.Setenv("HTTPS_PROXY", "http://stale.example:3128")
	t.Setenv("NO_PROXY", "")

	require.NoError(t, Apply(corpProxy))

	assert.Equal(t, "proxy.corp.example:8080", resolve(t, "https://app.datarobot.com/x").Host,
		"an explicit --proxy should win over the environment")
}

func TestApplyKeepsTLSSettings(t *testing.T) {
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

func TestApplyRejectsAMalformedProxy(t *testing.T) {
	// httpproxy never errors on these: it builds a nonsense URL, or resolves to
	// no proxy at all and lets the request go out direct. Either way the user
	// would see a confusing failure far from the value they typed.
	for _, bad := range []string{"://not a proxy", "not a proxy", "%%%", ""} {
		if bad == "" {
			continue // a blank value is the documented "leave it alone" case
		}

		t.Run(bad, func(t *testing.T) {
			restoreDefaultTransport(t)

			err := Apply(bad)

			require.Error(t, err, "%q should be rejected", bad)
			assert.Contains(t, err.Error(), "invalid proxy")
		})
	}
}

func TestApplyAcceptsABareHostAndPort(t *testing.T) {
	restoreDefaultTransport(t)
	t.Setenv("NO_PROXY", "")

	require.NoError(t, Apply("proxy.corp.example:8080"),
		"a bare host:port is what most corporate docs hand out")

	assert.Equal(t, "proxy.corp.example:8080", resolve(t, "https://app.datarobot.com/x").Host)
}

func TestPropagateEnvExportsTheProxyForPlugins(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("https_proxy", "")

	require.NoError(t, PropagateEnv(corpProxy))

	assert.Equal(t, corpProxy, os.Getenv("HTTP_PROXY"))
	assert.Equal(t, corpProxy, os.Getenv("HTTPS_PROXY"))
}

func TestPropagateEnvKeepsAnExistingEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("HTTPS_PROXY", "http://chosen.example:3128")

	require.NoError(t, PropagateEnv(corpProxy))

	assert.Equal(t, "http://chosen.example:3128", os.Getenv("HTTPS_PROXY"),
		"a value the user set deliberately must not be overwritten")
}
