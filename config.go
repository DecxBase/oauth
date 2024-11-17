package oauth

type oAuthConfig struct {
	ClientID     string
	ClientSecret string
}

type OAuthConfigCallback = func(*oAuthConfig)

func Config(client_id string, client_secret string, cbs ...OAuthConfigCallback) *oAuthConfig {
	cnf := &oAuthConfig{
		ClientID:     client_id,
		ClientSecret: client_secret,
	}

	for _, cb := range cbs {
		cb(cnf)
	}

	return cnf
}
