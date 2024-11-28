package oauth

import (
	"fmt"
	"strings"

	"github.com/DecxBase/core/types"
	"github.com/DecxBase/core/utils"
)

type facebookOAuthProvider struct {
	*OAuthProviderBase
	version string
}

func (p facebookOAuthProvider) Name() string {
	return "facebook"
}

func (p facebookOAuthProvider) FieldMappings() utils.DataMap[string] {
	return utils.MakeDataMap(map[string]string{
		"full_name": "name",
	})
}

func (p facebookOAuthProvider) Initialize(opts *oAuthOptions, scopes ...string) (*OAuthRequestResult, error) {
	rScopes := ResolveScopes(
		[]string{
			"public_profile",
		},
		scopes,
		"email",
	)

	uri := p.client.Clone().SetHost("www.facebook.com").
		SetPath(fmt.Sprintf("%s/dialog/oauth", p.version)).
		Set("client_id", p.config.ClientID()).
		Set("response_type", "code").
		SetIf(len(opts.AuthType) > 0, "auth_type", opts.AuthType).
		SetIf(len(rScopes) > 0, "scope", strings.Join(rScopes, ",")).
		Set("redirect_uri", opts.Redirect)

	return &OAuthRequestResult{
		Type: OAuthRequestRedirect,
		Data: uri.String(),
	}, nil
}

func (p facebookOAuthProvider) Callback(opts *oAuthOptions) (*OAuthToken, error) {
	data, err := p.RunTokenRequest(func(uri *oAuthURI) *oAuthURI {
		return uri.SetPath(fmt.Sprintf("%s/oauth/access_token", p.version)).
			Set("client_id", p.config.ClientID()).
			Set("client_secret", p.config.ClientSecret()).
			Set("code", opts.GetConfig("code").(string)).
			Set("redirect_uri", opts.Redirect)
	}, RequestOptions(), "access_token")

	if err != nil {
		return nil, err
	}
	return p.MakeTokenResult(data)
}

func (p facebookOAuthProvider) RefreshToken(token string) (*OAuthToken, error) {
	data, err := p.RunTokenRequest(func(uri *oAuthURI) *oAuthURI {
		return uri.SetPath(fmt.Sprintf("%s/oauth/access_token", p.version)).
			Set("client_id", p.config.ClientID()).
			Set("client_secret", p.config.ClientSecret()).
			Set("grant_type", "fb_exchange_token").
			Set("fb_exchange_token", token)
	}, RequestOptions(), "access_token")

	if err != nil {
		return nil, err
	}
	return p.MakeTokenResult(data)
}

func (p facebookOAuthProvider) TokenToUser(token *OAuthToken) (*OAuthUser, error) {
	fields, err := p.Get(token.AccessToken, []string{"id", "email"}, Options())
	if err != nil {
		return nil, err
	}

	return &OAuthUser{
		UserID:       fields["id"].(string),
		IdentityType: "email",
		Identity:     fields["email"].(string),
		AccessToken:  token.AccessToken,
		ExpiresIn:    token.ExpiresIn,
	}, nil
}

func (p facebookOAuthProvider) Get(token string, fields []string, opts *oAuthOptions) (types.JSONDumpData, error) {
	path := "me"
	if len(opts.RequestPath) > 0 {
		path = opts.RequestPath
	}

	return p.Call(func(uri *oAuthURI) *oAuthURI {
		return uri.SetPath(path).
			Set("access_token", token).
			Set("fields", strings.Join(fields, ","))
	}, RequestOptions())
}

func FacebookOAuth(config OAuthConfig) *facebookOAuthProvider {
	return &facebookOAuthProvider{
		version: "v21.0",
		OAuthProviderBase: &OAuthProviderBase{
			config: config,
			client: URIHost("graph.facebook.com"),
		},
	}
}
