package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/DecxBase/core/types"
)

type oAuthRequestOptions struct {
	Method  string
	Body    io.Reader
	Headers types.JSONStringData
}

type OAuthRequestOptionCallback = func(*oAuthRequestOptions)

func RequestOptions(cbs ...OAuthRequestOptionCallback) *oAuthRequestOptions {
	opts := &oAuthRequestOptions{
		Method:  http.MethodGet,
		Headers: make(types.JSONStringData),
	}

	for _, cb := range cbs {
		cb(opts)
	}

	return opts
}

func WithReqOptMethod(method string) OAuthRequestOptionCallback {
	return func(o *oAuthRequestOptions) {
		o.Method = method
	}
}

func WithReqOptBody(body io.Reader) OAuthRequestOptionCallback {
	return func(o *oAuthRequestOptions) {
		o.Body = body
	}
}

func WithReqHeader(key string, value string) OAuthRequestOptionCallback {
	return func(o *oAuthRequestOptions) {
		o.Headers[key] = value
	}
}

func OAuthRequestURI(uri *oAuthURI) ([]byte, error) {
	return OAuthRequest(uri, RequestOptions())
}

func OAuthRequest(uri *oAuthURI, opts *oAuthRequestOptions) ([]byte, error) {
	req, err := http.NewRequest(opts.Method, uri.String(), opts.Body)
	if len(opts.Headers) > 0 {
		for hkey, hval := range opts.Headers {
			req.Header.Set(hkey, hval)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("client: could not create request: %s", err)
	}

	res, err := http.DefaultClient.Do(req)

	if err != nil {
		return nil, fmt.Errorf("client: error making http request: %s", err)
	}

	resBody, err := io.ReadAll(res.Body)

	if err != nil {
		return nil, fmt.Errorf("client: could not read response body: %s", err)
	}

	return resBody, nil
}

func OAuthRequestJSON(uri *oAuthURI, opts *oAuthRequestOptions) (map[string]any, error) {
	res, err := OAuthRequest(uri, opts)

	if err != nil {
		return nil, err
	}

	var jsonData map[string]any
	err = json.Unmarshal(res, &jsonData)

	if err != nil {
		return nil, fmt.Errorf("failed to decode json response: %s", err)
	}

	return jsonData, nil
}
