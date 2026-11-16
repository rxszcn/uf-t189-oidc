package op_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestGetTokenIDAndSubjectFromToken_OpaqueAccessToken(t *testing.T) {
	ctx := context.Background()

	// Opaque access tokens are stored as the encrypted string "tokenID:subject"
	// and have no JWT claims attached. This used to panic because the returned
	// claims pointer was dereferenced unconditionally.
	token, err := testProvider.Crypto().Encrypt("tokenID:subject")
	require.NoError(t, err)

	var (
		tokenIDOrToken, subject string
		claims                  map[string]any
		ok                      bool
	)
	require.NotPanics(t, func() {
		tokenIDOrToken, subject, claims, ok = op.GetTokenIDAndSubjectFromToken(ctx, testProvider, token, oidc.AccessTokenType, false)
	})

	assert.True(t, ok)
	assert.Equal(t, "tokenID", tokenIDOrToken)
	assert.Equal(t, "subject", subject)
	assert.Empty(t, claims)
}

// TestTokenExchangeClientGrantParity holds both token endpoint dispatch paths
// (the legacy Provider handler and the op.Server handler) to the same answer
// for a client that is not registered for the token exchange grant:
// unauthorized_client, as RFC 6749, section 5.2 requires. A client registered
// for the grant must pass the whitelist on both paths and only fail later, on
// the invalid subject_token.
func TestTokenExchangeClientGrantParity(t *testing.T) {
	// A client registered for the device_code grant only.
	storage.RegisterClients(storage.DeviceClient("device", "secret"))

	form := url.Values{
		"grant_type":         {string(oidc.GrantTypeTokenExchange)},
		"subject_token":      {"token"},
		"subject_token_type": {string(oidc.AccessTokenType)},
	}

	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		wantError    string
	}{
		{
			name:         "client without token exchange grant is rejected",
			clientID:     "device",
			clientSecret: "secret",
			wantError:    string(oidc.UnauthorizedClient),
		},
		{
			name:         "client with token exchange grant passes the whitelist",
			clientID:     "web",
			clientSecret: "secret",
			// The whitelist lets the client through; the bogus subject_token
			// is what the exchange then fails on.
			wantError: string(oidc.InvalidRequest),
		},
	}

	for _, path := range authorizePaths(testProvider) {
		for _, tt := range tests {
			t.Run(path.name+"/"+tt.name, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodPost, testProvider.TokenEndpoint().Relative(), strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.SetBasicAuth(tt.clientID, tt.clientSecret)
				rec := httptest.NewRecorder()
				path.handler.ServeHTTP(rec, r)

				var body map[string]any
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
				assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
				assert.Equal(t, tt.wantError, body["error"], rec.Body.String())
			})
		}
	}
}
