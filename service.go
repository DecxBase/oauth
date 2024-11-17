package oauth

import (
	"fmt"

	"github.com/DecxBase/core/types"
)

type OAuthService[T comparable] struct {
	Options   *oAuthOptions
	Providers map[T]OAuthServiceProvider
}

func (p *OAuthService[T]) Register(name T, srv OAuthServiceProvider) *OAuthService[T] {
	p.Providers[name] = srv

	return p
}

func (s OAuthService[T]) GetProvider(name T) (OAuthServiceProvider, error) {
	val := s.Providers[name]

	if val == nil {
		return nil, OAuthError{
			Reason:  "provider",
			Message: fmt.Sprintf("Unknown provider: %+v", name),
		}
	}

	return val, nil
}

func (s OAuthService[T]) makeOptionCallbacks(cbs []OAuthOptionCallback) []OAuthOptionCallback {
	optsCBs := append(make([]OAuthOptionCallback, 0), WithOptions(s.Options))
	optsCBs = append(optsCBs, cbs...)

	return optsCBs
}

func (s OAuthService[T]) Initialize(name T, scopes []string, cbs ...OAuthOptionCallback) (*OAuthRequestResult, error) {
	service, err := s.GetProvider(name)
	if err != nil {
		return nil, err
	}

	result, err := service.Initialize(Options(s.makeOptionCallbacks(cbs)...), scopes...)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (s OAuthService[T]) Callback(name T, data types.JSONStringData, cbs ...OAuthOptionCallback) (*OAuthResult, error) {
	service, err := s.GetProvider(name)
	if err != nil {
		return nil, err
	}

	err = service.Validate(data)
	if err != nil {
		return nil, err
	}

	result, err := service.Callback(Options(s.makeOptionCallbacks(cbs)...))
	if err != nil {
		return nil, err
	}

	return result, nil
}

func Service[T comparable](opts ...*oAuthOptions) *OAuthService[T] {
	opt := Options()
	if len(opts) > 0 {
		opt = opts[0]
	}

	return &OAuthService[T]{
		Options:   opt,
		Providers: make(map[T]OAuthServiceProvider),
	}
}
