package oauth

type oAuthConfig struct {
	clientID     string
	clientSecret string
	extras       map[string]any
}

type OAuthConfigCallback = func(*oAuthConfig)

func (c oAuthConfig) ClientID() string {
	return c.clientID
}

func (c oAuthConfig) ClientSecret() string {
	return c.clientSecret
}

func (c oAuthConfig) GetExtra(key string) any {
	return c.extras[key]
}

func Config(client_id string, client_secret string, cbs ...OAuthConfigCallback) *oAuthConfig {
	cnf := &oAuthConfig{
		clientID:     client_id,
		clientSecret: client_secret,
		extras:       make(map[string]any),
	}

	for _, cb := range cbs {
		cb(cnf)
	}

	return cnf
}

func WithExtraConfig(key string, val any) OAuthConfigCallback {
	return func(o *oAuthConfig) {
		o.extras[key] = val
	}
}
