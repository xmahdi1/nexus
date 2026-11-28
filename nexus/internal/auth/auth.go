package auth

// Opaque session cookies replace the obsolete signed JWT cookie. The data
// encryption key is never used to sign an application session.
func CookieName() string { return "nexus_session" }
