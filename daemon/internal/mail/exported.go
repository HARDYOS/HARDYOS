package mail

// Helpers hardyd's side (internal/mail/manage) shares with root's.

// Invalid makes a ValidationError.
func Invalid(f string, a ...any) error { return invalid(f, a...) }

// ClipText drops control characters and shortens s to n bytes.
func ClipText(s string, n int) string { return clipText(s, n) }

// MatchTXT compares TXT records found with what rec asks for.
func MatchTXT(rec Record, txts []string) (string, string) { return matchTXT(rec, txts) }

// ValidPool reports whether p is a pool name.
func ValidPool(p string) bool { return poolRE.MatchString(p) }

// ValidSelector reports whether s is a DKIM selector.
func ValidSelector(s string) bool { return selectorRE.MatchString(s) }

// ValidSESUser reports whether u looks like an access key ID.
func ValidSESUser(u string) bool { return sesUserRE.MatchString(u) }

// hardyd-priv's mail operations (registered in internal/priv/mail_ops.go).
const (
	OpApply   = "mail.apply"
	OpStop    = "mail.stop"
	OpStatus  = "mail.status"
	OpDKIM    = "mail.dkim"
	OpCSR     = "mail.tls.csr"
	OpInstall = "mail.tls.install"
	OpFlush   = "mail.queue.flush"
	OpKick    = "mail.kick"
	OpDelete  = "mail.mailbox.delete"
	OpUsage   = "mail.usage"
)
