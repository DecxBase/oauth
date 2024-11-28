package oauth

import (
	"fmt"
	"strings"
)

type OAuthError struct {
	Reason  string
	Code    string
	Message string
}

func (e OAuthError) Error() string {
	msgs := make([]string, 0)

	if len(e.Code) > 0 && len(e.Reason) > 0 {
		msgs = append(msgs, fmt.Sprintf("[%s@%s]", e.Reason, e.Code))
	} else if len(e.Code) > 0 {
		msgs = append(msgs, fmt.Sprintf("[%s]", e.Code))
	} else if len(e.Reason) > 0 {
		msgs = append(msgs, fmt.Sprintf("[%s]", e.Reason))
	}

	if len(e.Message) > 0 {
		msgs = append(msgs, e.Message)
	}

	if len(msgs) > 0 {
		return strings.Join(msgs, " ")
	}

	return "Unknown oauth error"
}

func OAuthErrorToken() OAuthError {
	return OAuthError{
		Reason:  "invalid_token",
		Message: "Failed to retrieve access token",
	}
}

func OAuthErrorAccessDenied() OAuthError {
	return OAuthError{
		Reason:  "access_denied",
		Message: "Permission denied",
	}
}

func OAuthErrorJWTFailed() OAuthError {
	return OAuthError{
		Reason:  "jwt_token",
		Message: "Failed to parse JWT token",
	}
}

func OAuthErrorDecodeFailed() OAuthError {
	return OAuthError{
		Reason:  "decode",
		Message: "Failed to decode data",
	}
}

func OAuthErrorUnimplemented(name string, method string) OAuthError {
	return OAuthError{
		Reason:  "unimplemented",
		Message: fmt.Sprintf("Service [%s] hasn't implmented method [%s]", name, method),
	}
}
