package oauth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/DecxBase/core/types"
	"github.com/DecxBase/core/utils"
)

type googleOAuthProvider struct {
	*OAuthProviderBase
}

func (p googleOAuthProvider) Name() string {
	return "google"
}

func (p googleOAuthProvider) Validate(data types.JSONStringData) error {
	error_reason := data["error"]
	if len(error_reason) > 0 {
		if utils.CheckContains([]string{
			"access_denied",
			"invalid_grant",
		}, error_reason) {
			return OAuthErrorAccessDenied()
		}

		return OAuthError{
			Code:    data["code"],
			Reason:  error_reason,
			Message: data["error_description"],
		}
	}

	return nil
}

func (p googleOAuthProvider) Initialize(opts *oAuthOptions, scopes ...string) (*OAuthRequestResult, error) {
	rScopes := ResolveScopes(
		[]string{
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		scopes,
		"https://www.googleapis.com/auth/userinfo.email",
	)

	uri := p.client.Clone().SetPath("o/oauth2/v2/auth").
		Set("client_id", p.config.ClientID()).
		Set("response_type", "code").
		Set("scope", strings.Join(rScopes, " ")).
		Set("redirect_uri", opts.Redirect)

	return &OAuthRequestResult{
		Type: OAuthRequestRedirect,
		Data: uri.String(),
	}, nil
}

func (p googleOAuthProvider) Callback(opts *oAuthOptions) (*OAuthToken, error) {
	data, err := p.RunTokenRequest(func(uri *oAuthURI) *oAuthURI {
		return uri.SetPath("o/oauth2/token").
			SetBody("client_id", p.config.ClientID()).
			SetBody("client_secret", p.config.ClientSecret()).
			SetBody("grant_type", "authorization_code").
			SetBody("code", opts.GetConfig("code").(string)).
			SetBody("redirect_uri", opts.Redirect)
	}, RequestOptions(
		WithReqOptMethod(http.MethodPost),
	), "access_token")

	if err != nil {
		return nil, err
	}
	return p.MakeTokenResult(data)
}

func (p googleOAuthProvider) RefreshToken(token string) (*OAuthToken, error) {
	data, err := p.RunTokenRequest(func(uri *oAuthURI) *oAuthURI {
		return uri.SetPath("o/oauth2/token").
			SetBody("client_id", p.config.ClientID()).
			SetBody("client_secret", p.config.ClientSecret()).
			SetBody("grant_type", "refresh_token").
			SetBody("access_type", "offline").
			SetBody("prompt", "consent").
			SetBody("refresh_token", token)
	}, RequestOptions(
		WithReqOptMethod(http.MethodPost),
	), "access_token")

	if err != nil {
		return nil, err
	}
	return p.MakeTokenResult(data)
}

func (p googleOAuthProvider) TokenToUser(token *OAuthToken) (*OAuthUser, error) {
	payload, err := p.DecodeIDToken(token.IDToken)
	if err != nil {
		return nil, err
	}

	return &OAuthUser{
		UserID:       payload["sub"].(string),
		IdentityType: "email",
		Identity:     payload["email"].(string),
		AccessToken:  token.AccessToken,
		ExpiresIn:    token.ExpiresIn,
	}, nil
}

func (p googleOAuthProvider) Get(token string, fields []string, opts *oAuthOptions) (types.JSONDumpData, error) {
	data, err := p.Call(func(uri *oAuthURI) *oAuthURI {
		return uri.SetHost("www.googleapis.com").
			SetPath("oauth2/v1/userinfo").
			SetBody("alt", "json")
	}, RequestOptions(
		WithReqHeader("Authorization", fmt.Sprintf("Bearer %s", token)),
	))

	if err != nil {
		return nil, err
	}
	return utils.PluckFields(data, fields), nil
}

func GoogleOAuth(config OAuthConfig) *googleOAuthProvider {
	return &googleOAuthProvider{
		OAuthProviderBase: &OAuthProviderBase{
			config: config,
			client: URIHost("accounts.google.com"),
		},
	}
}
