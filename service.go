package oauth

import (
	"fmt"

	"github.com/DecxBase/core/types"
	"github.com/DecxBase/core/utils"
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

func (s OAuthService[T]) Callback(name T, data types.JSONStringData, cbs ...OAuthOptionCallback) (*OAuthToken, error) {
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

func (s OAuthService[T]) RefreshToken(name T, token string) (*OAuthToken, error) {
	service, err := s.GetProvider(name)
	if err != nil {
		return nil, err
	}

	result, err := service.RefreshToken(token)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (s OAuthService[T]) TokenToUser(name T, token *OAuthToken) (*OAuthUser, error) {
	service, err := s.GetProvider(name)
	if err != nil {
		return nil, err
	}

	result, err := service.TokenToUser(token)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (s OAuthService[T]) Get(name T, token string, fields []string, opts *oAuthOptions) (types.JSONDumpData, error) {
	if len(fields) < 1 {
		return make(types.JSONDumpData), nil
	}

	service, err := s.GetProvider(name)
	if err != nil {
		return nil, err
	}

	mapped := utils.NewDataMap[string]()
	mappings := service.FieldMappings()
	theFields := utils.MapData(utils.MakeDataList(fields), func(field string) string {
		if mappings.Contains(field) {
			return mapped.Set(mappings.Get(field), field)
		}

		return field
	})

	result, err := service.Get(token, theFields, opts)
	if err != nil {
		return nil, err
	}

	newResult := make(types.JSONDumpData)
	for key, val := range result {
		if mapped.Contains(key) {
			newResult[mapped.Get(key)] = val
		} else {
			newResult[key] = val
		}
	}

	return newResult, nil
}

func (s OAuthService[T]) GetRaw(name T, token string, fields []string, opts *oAuthOptions) (types.JSONDumpData, error) {
	service, err := s.GetProvider(name)
	if err != nil {
		return nil, err
	}

	result, err := service.Get(token, fields, opts)
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
