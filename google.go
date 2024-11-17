package oauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/DecxBase/core/types"
	"github.com/DecxBase/core/utils"
)

type googleOAuthProvider struct {
	config *oAuthConfig
}

func (p googleOAuthProvider) Name() string {
	return "google"
}

func (p googleOAuthProvider) Initialize(opts *oAuthOptions, scopes ...string) (*OAuthRequestResult, error) {
	rScopes := ResolveScopes(
		[]string{
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		scopes,
		"https://www.googleapis.com/auth/userinfo.email",
	)

	uri := URI("accounts.google.com", "o/oauth2/v2/auth").
		Set("client_id", p.config.ClientID).
		Set("response_type", "code").
		Set("scope", strings.Join(rScopes, " ")).
		Set("redirect_uri", opts.Redirect)

	return &OAuthRequestResult{
		Type: OAuthRequestRedirect,
		Data: uri.String(),
	}, nil
}

func (p googleOAuthProvider) Callback(opts *oAuthOptions) (*OAuthResult, error) {
	uri := URI("accounts.google.com", "o/oauth2/token").
		SetBody("client_id", p.config.ClientID).
		SetBody("client_secret", p.config.ClientSecret).
		SetBody("grant_type", "authorization_code").
		SetBody("code", opts.GetConfig("code").(string)).
		SetBody("redirect_uri", opts.Redirect)

	res, err := OAuthRequest(*uri, RequestOptions(
		WithReqOptMethod(http.MethodPost),
		WithReqOptBody(bytes.NewBuffer(uri.GetPayload())),
	))
	if err != nil {
		return nil, err
	}

	var data types.JSONStringData
	json.Unmarshal(res, &data)

	access_token := data["access_token"]
	if len(access_token) < 1 {
		return nil, OAuthErrorToken()
	}

	return &OAuthResult{
		AccessToken: access_token,
		IDToken:     data["id_token"],
		TokenType:   data["token_type"],
		Scopes:      strings.Split(data["scope"], " "),
		ExpiresIn:   utils.StringToInt(data["expires_in"]),
	}, nil
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

func OAuthGoogle(config *oAuthConfig) *googleOAuthProvider {
	return &googleOAuthProvider{
		config: config,
	}
}
