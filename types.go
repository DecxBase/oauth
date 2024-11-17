package oauth

import "github.com/DecxBase/core/types"

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

type OAuthResult struct {
	AccessToken string
	IDToken     string
	ExpiresIn   int
	TokenType   string
	Scopes      []string
}

type OAuthServiceProvider interface {
	Name() string
	Initialize(*oAuthOptions, ...string) (*OAuthRequestResult, error)
	Callback(*oAuthOptions) (*OAuthResult, error)
	Validate(types.JSONStringData) error
}
