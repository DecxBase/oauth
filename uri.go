package oauth

import (
	"encoding/json"
	"net/url"
)

type oAuthURI struct {
	Schema string
	Host   string
	Path   string
	Query  map[string]string
	Body   map[string]any

	uri url.URL
}

func (u *oAuthURI) SetIf(valid bool, key string, val string) *oAuthURI {
	if valid {
		return u.Set(key, val)
	}

	return u
}

func (u *oAuthURI) Set(key string, val string) *oAuthURI {
	u.Query[key] = val
	return u
}

func (u *oAuthURI) SetBodyIf(valid bool, key string, val string) *oAuthURI {
	if valid {
		return u.SetBody(key, val)
	}

	return u
}

func (u *oAuthURI) SetBody(key string, val string) *oAuthURI {
	u.Body[key] = val
	return u
}

func (u oAuthURI) GetPayload() []byte {
	bytes, err := json.Marshal(u.Body)

	if err != nil {
		return nil
	}

	return bytes
}

func (u *oAuthURI) generate() {
	u.uri = url.URL{
		Scheme: u.Schema,
		Host:   u.Host,
		Path:   u.Path,
	}

	q := u.uri.Query()

	for key, val := range u.Query {
		q.Set(key, val)
	}

	u.uri.RawQuery = q.Encode()
}

func (u oAuthURI) Clone() *oAuthURI {
	return &oAuthURI{
		Schema: u.Schema,
		Host:   u.Host,
		Path:   u.Path,
		Query:  u.Query,
		Body:   u.Body,
	}
}

func (u oAuthURI) String() string {
	u.generate()
	return u.uri.String()
}

func URI(host string, path string) *oAuthURI {
	return &oAuthURI{
		Schema: "https",
		Host:   host,
		Path:   path,
		Query:  make(map[string]string),
		Body:   make(map[string]any),
	}
}
