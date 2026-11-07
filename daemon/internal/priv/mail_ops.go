package priv

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hardyos/hardyos/daemon/internal/mail"
)

// The mail server's operations (docs/mail.md). hardyd sends a validated
// description (mail.RootConfig), never file contents: root validates it
// again and renders Postfix's, Dovecot's, Rspamd's and Radicale's
// configuration itself. Keys (DKIM, TLS) are made by root and never
// leave it; deleting a mailbox's messages needs its address typed again.

func mailErr(err error) error {
	var ve *mail.ValidationError
	if errors.As(err, &ve) {
		return Errorf(CodeBadArgs, "%v", err)
	}
	return err
}

// RegisterMail adds the mail operations.
func RegisterMail(s *Server, r *mail.Root) {
	s.Handle(mail.OpApply, typed(func(ctx context.Context, a mail.ApplyArgs) (any, error) {
		res, err := r.Apply(ctx, a)
		return res, mailErr(err)
	}))
	s.Handle(mail.OpStop, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return map[string]bool{"stopped": true}, mailErr(r.Stop(ctx))
	})
	s.Handle(mail.OpStatus, typed(func(ctx context.Context, a mail.StatusArgs) (any, error) {
		res, err := r.Status(ctx, a)
		return res, mailErr(err)
	}))
	s.Handle(mail.OpDKIM, typed(func(ctx context.Context, a mail.DKIMArgs) (any, error) {
		res, err := r.DKIM(ctx, a)
		return res, mailErr(err)
	}))
	s.Handle(mail.OpCSR, typed(func(ctx context.Context, a mail.CSRArgs) (any, error) {
		res, err := r.CSR(ctx, a)
		return res, mailErr(err)
	}))
	s.Handle(mail.OpInstall, typed(func(ctx context.Context, a mail.InstallArgs) (any, error) {
		res, err := r.Install(ctx, a)
		return res, mailErr(err)
	}))
	s.Handle(mail.OpFlush, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return map[string]bool{"flushed": true}, mailErr(r.Flush(ctx))
	})
	s.Handle(mail.OpKick, typed(func(ctx context.Context, a mail.AddressArgs) (any, error) {
		return map[string]bool{"kicked": true}, mailErr(r.Kick(ctx, a))
	}))
	s.Handle(mail.OpDelete, typed(func(ctx context.Context, a mail.DeleteArgs) (any, error) {
		return map[string]bool{"deleted": true}, mailErr(r.DeleteMailbox(ctx, a))
	}))
	s.Handle(mail.OpUsage, typed(func(ctx context.Context, a mail.UsageArgs) (any, error) {
		res, err := r.Usage(ctx, a)
		return res, mailErr(err)
	}))
	if s.QuietOps == nil {
		s.QuietOps = map[string]bool{}
	}
	s.QuietOps[mail.OpStatus] = true
}
