package oauth

type oAuthOptions struct {
	Redirect string
	AuthType string
	Config   map[string]any
}

func (o oAuthOptions) GetConfig(key string) any {
	return o.Config[key]
}

type OAuthOptionCallback = func(*oAuthOptions)

func Options(cbs ...OAuthOptionCallback) *oAuthOptions {
	opts := &oAuthOptions{}

	for _, cb := range cbs {
		cb(opts)
	}

	return opts
}

func WithOptions(opts *oAuthOptions) OAuthOptionCallback {
	return func(o *oAuthOptions) {
		o.Redirect = opts.Redirect
		o.AuthType = opts.AuthType
		o.Config = opts.Config
	}
}

func WithOptRedirect(redirect string) OAuthOptionCallback {
	return func(o *oAuthOptions) {
		o.Redirect = redirect
	}
}

func WithOptAuthType(auth_type string) OAuthOptionCallback {
	return func(o *oAuthOptions) {
		o.AuthType = auth_type
	}
}

func WithOptConfig(key string, val any) OAuthOptionCallback {
	return func(o *oAuthOptions) {
		if o.Config == nil {
			o.Config = make(map[string]any)
		}

		o.Config[key] = val
	}
}
