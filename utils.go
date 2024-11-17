package oauth

func ResolveScopes(defs []string, data []string, extras ...string) []string {
	scopes := make([]string, 0)
	scopes = append(scopes, defs...)

	if len(data) > 0 {
		scopes = append(scopes, data...)
	} else if len(extras) > 0 {
		scopes = append(scopes, extras...)
	}

	return scopes
}
