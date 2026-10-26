package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
)

func (s *Server) handleAppCatalogs(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	list, err := s.appStore().Catalogs(r.Context())
	if err != nil {
		s.writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// AppCatalogRequest imports a catalog, or refreshes one already imported.
type AppCatalogRequest struct {
	URL string `json:"url"`
}

func (s *Server) handleAddAppCatalog(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req AppCatalogRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	st := s.appStore()
	u2, err := appstore.CheckCatalogURL(req.URL)
	if err != nil {
		s.writeAppError(w, err)
		return
	}
	existing, err := st.Catalogs(r.Context())
	if err != nil {
		s.writeAppError(w, err)
		return
	}
	for _, c := range existing {
		if c.URL == u2.String() {
			got, err := st.RefreshCatalog(r.Context(), c.ID)
			if err != nil {
				s.record(r, u, "apps.catalog.refresh", c.URL, audit.Failure, err.Error())
				s.writeAppError(w, catalogProblem(err))
				return
			}
			s.record(r, u, "apps.catalog.refresh", c.URL, audit.Success, strconv.Itoa(len(got.Apps))+" apps")
			writeJSON(w, http.StatusOK, got)
			return
		}
	}
	c, err := st.AddCatalog(r.Context(), req.URL, u.Username)
	if err != nil {
		s.record(r, u, "apps.catalog.add", req.URL, audit.Failure, err.Error())
		s.writeAppError(w, err)
		return
	}
	s.record(r, u, "apps.catalog.add", c.URL, audit.Success, c.Name+": "+strconv.Itoa(len(c.Apps))+" apps")
	writeJSON(w, http.StatusOK, c)
}

// catalogProblem shows a refresh failure (a network error, say) as the
// person's problem to look at rather than an internal error.
func catalogProblem(err error) error {
	if isErr(err, appstore.ErrNotFound, appstore.ErrNoDB) {
		return err
	}
	var p apps.Problems
	if errors.As(err, &p) {
		return p
	}
	return apps.Problems{err.Error()}
}

// AppCatalogRemoveRequest removes an imported catalog.
type AppCatalogRemoveRequest struct {
	ID int64 `json:"id"`
}

func (s *Server) handleRemoveAppCatalog(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req AppCatalogRemoveRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	c, err := s.appStore().RemoveCatalog(r.Context(), req.ID)
	if err != nil {
		s.writeAppError(w, err)
		return
	}
	s.record(r, u, "apps.catalog.remove", c.URL, audit.Success, c.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAppCustom(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req appstore.CustomApp
	if !decodeJSON(w, r, &req) {
		return
	}
	e, err := s.appStore().BuildCustom(req)
	if err != nil {
		s.writeAppError(w, err)
		return
	}
	s.record(r, u, "apps.custom", e.ID+" "+e.Version, audit.Success, "sha256 "+e.Ref)
	plan, err := s.appPlan(r.Context(), AppPackageRef{Source: e.Source, Ref: e.Ref})
	if err != nil {
		s.writeAppOrPrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}
