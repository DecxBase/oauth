package oauth

import (
	"github.com/DecxBase/core/types"
	"github.com/DecxBase/core/utils"
)

type OAuthRequestType int

const (
	OAuthRequestRedirect OAuthRequestType = iota + 1 // EnumIndex = 1
	OAuthRequestData                                 // EnumIndex = 2
)

func (r OAuthRequestType) String() string {
	return []string{"redirect", "data"}[r-1]
}

type OAuthRequestResult struct {
	Type OAuthRequestType
	Data any
}

type OAuthToken struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type OAuthUser struct {
	UserID       string
	IdentityType string
	Identity     string
	AccessToken  string
	ExpiresIn    int64
}

type OAuthConfig interface {
	ClientID() string
	ClientSecret() string
	GetExtra(string) any
}

type OAuthRawCallback = func(*oAuthURI) *oAuthURI

type OAuthServiceProvider interface {
	Name() string
	FieldMappings() utils.DataMap[string]
	Validate(types.JSONStringData) error
	Initialize(*oAuthOptions, ...string) (*OAuthRequestResult, error)
	Callback(*oAuthOptions) (*OAuthToken, error)
	RefreshToken(string) (*OAuthToken, error)
	TokenToUser(*OAuthToken) (*OAuthUser, error)
	Get(string, []string, *oAuthOptions) (types.JSONDumpData, error)
	Call(OAuthRawCallback, *oAuthRequestOptions) (types.JSONDumpData, error)
}
