package sites

import (
	"net/http"
	"strings"
)

// cookiePairs joins every name=value pair the responses set, in order, so a
// later request can send the session back. A later value replaces an earlier
// one with the same name, and an empty value clears it.
func cookiePairs(headers ...http.Header) string {
	var names []string
	values := map[string]string{}
	for _, header := range headers {
		for _, line := range header.Values("Set-Cookie") {
			pair, _, _ := strings.Cut(line, ";")
			name, value, ok := strings.Cut(pair, "=")
			name = strings.TrimSpace(name)
			if !ok || name == "" {
				continue
			}
			if _, seen := values[name]; !seen {
				names = append(names, name)
			}
			values[name] = strings.TrimSpace(value)
		}
	}
	var out []string
	for _, name := range names {
		if values[name] != "" {
			out = append(out, name+"="+values[name])
		}
	}
	return strings.Join(out, "; ")
}
