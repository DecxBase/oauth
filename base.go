package oauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DecxBase/core/types"
	"github.com/DecxBase/core/utils"
)

type OAuthProviderBase struct {
	client *oAuthURI
	config OAuthConfig
}

func (p OAuthProviderBase) Name() string {
	return "unknown"
}

func (p OAuthProviderBase) FieldMappings() utils.DataMap[string] {
	return utils.MakeDataMap(map[string]string{})
}

func (p OAuthProviderBase) Validate(data types.JSONStringData) error {
	error_reason := data["error"]
	if len(error_reason) > 0 {
		if utils.CheckContains([]string{
			"access_denied",
			"invalid_grant",
		}, error_reason) {
			return OAuthErrorAccessDenied()
		}

		return OAuthError{
			Code:    data["code"],
			Reason:  error_reason,
			Message: data["error_description"],
		}
	}

	error_code := data["error_code"]
	error_subcode := data["error_subcode"]
	if len(error_code) > 0 {
		return OAuthError{
			Code:    error_code,
			Reason:  data["error_reason"],
			Message: data["error_description"],
		}
	} else if len(error_subcode) > 0 {
		return OAuthError{
			Code:    fmt.Sprintf("%s.%s", data["code"], error_subcode),
			Reason:  data["type"],
			Message: data["message"],
		}
	}

	return nil
}

func (p OAuthProviderBase) Initialize(opts *oAuthOptions, scopes ...string) (*OAuthRequestResult, error) {
	return nil, OAuthErrorUnimplemented(p.Name(), "Initialize")
}

func (p OAuthProviderBase) Callback(opts *oAuthOptions) (*OAuthToken, error) {
	return nil, OAuthErrorUnimplemented(p.Name(), "Callback")
}

func (p OAuthProviderBase) RefreshToken(token string) (*OAuthToken, error) {
	return nil, OAuthErrorUnimplemented(p.Name(), "RefreshToken")
}

func (p OAuthProviderBase) TokenToUser(token *OAuthToken) (*OAuthUser, error) {
	return nil, OAuthErrorUnimplemented(p.Name(), "TokenToUser")
}

func (p OAuthProviderBase) Get(token string, fields []string, opts *oAuthOptions) (types.JSONDumpData, error) {
	return nil, OAuthErrorUnimplemented(p.Name(), "Get")
}

func (p OAuthProviderBase) Call(cb OAuthRawCallback, opts *oAuthRequestOptions) (types.JSONDumpData, error) {
	uri := cb(p.client.Clone())
	if utils.CheckContains([]string{
		"POST",
		"PATCH",
		"PUT",
	}, opts.Method) && len(uri.Body) > 0 {
		WithReqOptBody(bytes.NewBuffer(uri.GetPayload()))(opts)
	}

	res, err := OAuthRequest(uri, opts)
	if err != nil {
		return nil, err
	}

	var data types.JSONDumpData
	err = json.Unmarshal(res, &data)

	return data, err
}

func (p OAuthProviderBase) RunTokenRequest(cb OAuthRawCallback, opts *oAuthRequestOptions, key string) (types.JSONDumpData, error) {
	data, err := p.Call(cb, opts)
	if err != nil {
		return nil, err
	}

	errInfo := data["error"]
	if errInfo != nil {
		if utils.IsType[string](errInfo) {
			err = p.Validate(utils.ToJsonString(data))
		} else {
			err = p.Validate(utils.ToJsonString(errInfo))
		}

		if err != nil {
			return nil, err
		}
	}

	access_token := data[key]
	if access_token != nil && len(access_token.(string)) < 1 {
		return nil, OAuthErrorToken()
	}

	return data, nil
}

func (p OAuthProviderBase) MakeTokenResult(data types.JSONDumpData) (*OAuthToken, error) {
	var result OAuthToken
	err := utils.MapToStruct(data, &result)

	if err != nil {
		return nil, err
	}

	return &result, nil
}

func (p OAuthProviderBase) DecodeIDToken(token string) (types.JSONDumpData, error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil, OAuthErrorJWTFailed()
	}

	payloadData, err := p.Base64Decode(segments[1])
	if err != nil {
		return nil, err
	}

	return payloadData, err
}

func (p OAuthProviderBase) Base64Decode(str string) (types.JSONDumpData, error) {
	dataBytes, err := base64.RawStdEncoding.DecodeString(str)
	if err != nil {
		return nil, OAuthErrorJWTFailed()
	}

	var jsonData types.JSONDumpData
	err = json.Unmarshal(dataBytes, &jsonData)

	if err != nil {
		return nil, OAuthErrorDecodeFailed()
	}
	return jsonData, nil
}
