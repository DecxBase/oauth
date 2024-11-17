package oauth

import (
	"encoding/json"
	"strings"

	"github.com/DecxBase/core/types"
	"github.com/DecxBase/core/utils"
)

type facebookOAuthProvider struct {
	config *oAuthConfig
}

func (p facebookOAuthProvider) Name() string {
	return "facebook"
}

func (p facebookOAuthProvider) Initialize(opts *oAuthOptions, scopes ...string) (*OAuthRequestResult, error) {
	rScopes := ResolveScopes(
		[]string{
			"public_profile",
		},
		scopes,
		"email",
	)

	uri := URI("www.facebook.com", "v21.0/dialog/oauth").
		Set("client_id", p.config.ClientID).
		Set("response_type", "code").
		SetIf(len(opts.AuthType) > 0, "auth_type", opts.AuthType).
		SetIf(len(rScopes) > 0, "scope", strings.Join(rScopes, ",")).
		Set("redirect_uri", opts.Redirect)

	return &OAuthRequestResult{
		Type: OAuthRequestRedirect,
		Data: uri.String(),
	}, nil
}

func (p facebookOAuthProvider) Callback(opts *oAuthOptions) (*OAuthResult, error) {
	uri := URI("graph.facebook.com", "v21.0/oauth/access_token").
		Set("client_id", p.config.ClientID).
		Set("client_secret", p.config.ClientSecret).
		Set("code", opts.GetConfig("code").(string)).
		Set("redirect_uri", opts.Redirect)

	res, err := OAuthRequest(*uri, RequestOptions())
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
		TokenType:   data["token_type"],
		ExpiresIn:   utils.StringToInt(data["expires_in"]),
	}, nil
}

func (p facebookOAuthProvider) Validate(data types.JSONStringData) error {
	error_code := data["error_code"]
	if len(error_code) > 0 {
		return OAuthError{
			Code:    error_code,
			Reason:  data["error_reason"],
			Message: data["error_description"],
		}
	}

	return nil
}

func OAuthFacebook(config *oAuthConfig) *facebookOAuthProvider {
	return &facebookOAuthProvider{
		config: config,
	}
}
