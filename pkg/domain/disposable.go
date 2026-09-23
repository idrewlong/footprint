package domain

// BuiltinDisposable returns the built-in disposable-domain list.
func BuiltinDisposable() map[string]struct{} {
	return map[string]struct{}{
		"mailinator.com":    {},
		"guerrillamail.com": {},
		"yopmail.com":       {},
		"tempmail.com":      {},
		"10minutemail.com":  {},
		"trashmail.com":     {},
		"getnada.com":       {},
		"dispostable.com":   {},
		"sharklasers.com":   {},
		"maildrop.cc":       {},
	}
}
