package office

import "context"

// OpenSessions lists the documents open now (sessions the Document Server
// hasn't closed, heard from within a day), newest first.
func (s *Service) OpenSessions(ctx context.Context) ([]*Session, error) {
	if s.DB == nil {
		return nil, nil
	}
	list, err := s.db().openSessions(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := make([]*Session, 0, len(list))
	for _, x := range list {
		if now.Sub(x.UpdatedAt) <= idleSession {
			out = append(out, x)
		}
	}
	s.db().prune(ctx, now)
	return out, nil
}

// ActiveNames are the names of the people in a session now.
func (s *Service) ActiveNames(ctx context.Context, sess *Session) ([]string, error) {
	list, err := s.db().participants(ctx, sess.Key)
	if err != nil {
		return nil, err
	}
	in := map[string]bool{}
	for _, id := range sess.Active {
		in[id] = true
	}
	var out []string
	for _, p := range list {
		if in[p.ID] {
			out = append(out, p.Name)
		}
	}
	return out, nil
}

// CloseAll ends every open session (the office suite was turned off).
func (s *Service) CloseAll(ctx context.Context, why string) error {
	list, err := s.db().openSessions(ctx)
	if err != nil {
		return err
	}
	for _, x := range list {
		if err := s.db().setState(ctx, x.Key, StateClosed, why, s.now()); err != nil {
			return err
		}
	}
	return nil
}
