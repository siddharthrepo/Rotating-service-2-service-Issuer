package controller

import (
	"context"
	"html/template"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/apperr"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/constants"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/controller/render"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/middleware"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/web"
)

type authService interface {
	Login(ctx context.Context, email, password, remoteIP string) (string, *structs.User, error)
	Resolve(ctx context.Context, rawCookie string) (*structs.User, error)
	Logout(ctx context.Context, rawCookie string, user *structs.User) error
}

type graphService interface {
	Build(ctx context.Context) (*structs.Graph, error)
}

// Dashboard is the human-facing UI.
type Dashboard struct {
	tpl      *template.Template
	auth     authService
	graph    graphService
	registry registryService
	grants   grantsService
	revoke   revocationService
	audit    auditService
	secure   bool
}

func NewDashboard(auth authService, graph graphService, registry registryService,
	grants grantsService, revoke revocationService, audit auditService, secureCookies bool) (*Dashboard, error) {
	tpl, err := template.New("").Funcs(template.FuncMap{
		"ago": humaniseTime,
	}).ParseFS(web.Templates, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Dashboard{
		tpl: tpl, auth: auth, graph: graph, registry: registry,
		grants: grants, revoke: revoke, audit: audit, secure: secureCookies,
	}, nil
}

func (d *Dashboard) LoginPage(c *gin.Context) {
	d.renderPage(c, http.StatusOK, "login", gin.H{})
}

func (d *Dashboard) Login(c *gin.Context) {
	var req structs.LoginRequest
	if err := c.ShouldBind(&req); err != nil {
		d.renderPage(c, http.StatusBadRequest, "login", gin.H{"Error": "Email and password are required."})
		return
	}

	raw, user, err := d.auth.Login(c.Request.Context(), req.Email, req.Password, c.ClientIP())
	if err != nil {

		d.renderPage(c, http.StatusUnauthorized, "login", gin.H{"Error": "Invalid email or password."})
		return
	}

	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(constants.SessionCookie, raw, int(constants.SessionLifetime.Seconds()),
		"/", "", d.secure, true)
	_ = user
	c.Redirect(http.StatusSeeOther, "/")
}

func (d *Dashboard) Logout(c *gin.Context) {
	if raw, err := c.Cookie(constants.SessionCookie); err == nil {
		user, _ := middleware.UserFrom(c)
		_ = d.auth.Logout(c.Request.Context(), raw, user)
	}
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(constants.SessionCookie, "", -1, "/", "", d.secure, true)
	c.Redirect(http.StatusSeeOther, "/login")
}

func (d *Dashboard) GraphPage(c *gin.Context) {
	d.renderShell(c, "graph", "Graph", gin.H{})
}

// GraphData feeds the Cytoscape renderer.
func (d *Dashboard) GraphData(c *gin.Context) {
	g, err := d.graph.Build(c.Request.Context())
	if err != nil {
		render.Error(c, err)
		return
	}
	render.OK(c, g)
}

func (d *Dashboard) ServicesPage(c *gin.Context) {
	services, err := d.registry.List(c.Request.Context(), structs.ServiceFilter{Limit: constants.MaxPageLimit})
	if err != nil {
		render.Error(c, err)
		return
	}
	graph, err := d.graph.Build(c.Request.Context())
	if err != nil {
		render.Error(c, err)
		return
	}
	d.renderShell(c, "services", "Services", gin.H{
		"Services": servicesWithDegree(services, graph),
	})
}

func (d *Dashboard) GrantsPage(c *gin.Context) {
	user, _ := middleware.UserFrom(c)
	rows, err := d.grantRows(c, user)
	if err != nil {
		render.Error(c, err)
		return
	}
	d.renderShell(c, "grants", "Grants", gin.H{"Grants": rows})
}

func (d *Dashboard) AuditPage(c *gin.Context) {
	entries, err := d.audit.List(c.Request.Context(), structs.AuditFilter{Limit: 100})
	if err != nil {
		render.Error(c, err)
		return
	}
	d.renderShell(c, "audit", "Audit", gin.H{"Entries": auditRows(entries)})
}

func (d *Dashboard) RevokeGrant(c *gin.Context) {
	d.mutateGrant(c, func(ctx context.Context, id uint64, actor structs.Actor, reason string) error {
		_, err := d.revoke.RevokeGrant(ctx, id, actor, reason)
		return err
	})
}

func (d *Dashboard) RotateGrant(c *gin.Context) {
	d.mutateGrant(c, func(ctx context.Context, id uint64, actor structs.Actor, reason string) error {
		_, err := d.revoke.ForceRotate(ctx, id, actor, reason)
		return err
	})
}

func (d *Dashboard) mutateGrant(c *gin.Context, action func(context.Context, uint64, structs.Actor, string) error) {
	id, err := pathUint(c, "id")
	if err != nil {
		c.String(http.StatusBadRequest, "invalid grant id")
		return
	}

	reason := c.GetHeader("HX-Prompt")
	if reason == "" {
		reason = "no reason given"
	}

	if err := action(c.Request.Context(), id, middleware.ActorFrom(c), reason); err != nil {

		c.String(http.StatusOK, `<tr id="grant-%d"><td colspan="8" class="error">%s</td></tr>`,
			id, template.HTMLEscapeString(apperr.As(err).Message))
		return
	}

	user, _ := middleware.UserFrom(c)
	detail, err := d.grants.ByID(c.Request.Context(), id)
	if err != nil {
		render.Error(c, err)
		return
	}
	d.renderFragment(c, "grantrow", toGrantRow(detail, nil, user))
}

func humaniseTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format("2006-01-02 15:04:05")
}

func (d *Dashboard) renderShell(c *gin.Context, view, title string, data gin.H) {
	user, _ := middleware.UserFrom(c)
	data["Nav"] = view
	data["Title"] = title
	data["User"] = user

	tpl, err := template.New("").Funcs(template.FuncMap{"ago": humaniseTime}).
		ParseFS(web.Templates, "templates/layout.html", "templates/"+view+".html")
	if err != nil {
		render.Error(c, err)
		return
	}
	c.Status(http.StatusOK)
	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := tpl.ExecuteTemplate(c.Writer, "layout", data); err != nil {
		_ = c.Error(err)
	}
}

func (d *Dashboard) renderPage(c *gin.Context, status int, name string, data gin.H) {
	c.Status(status)
	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := d.tpl.ExecuteTemplate(c.Writer, name, data); err != nil {
		_ = c.Error(err)
	}
}

func (d *Dashboard) renderFragment(c *gin.Context, name string, data any) {
	tpl, err := template.New("").Funcs(template.FuncMap{"ago": humaniseTime}).
		ParseFS(web.Templates, "templates/grants.html")
	if err != nil {
		render.Error(c, err)
		return
	}
	c.Status(http.StatusOK)
	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := tpl.ExecuteTemplate(c.Writer, name, data); err != nil {
		_ = c.Error(err)
	}
}

func (d *Dashboard) grantRows(c *gin.Context, user *structs.User) ([]grantRow, error) {
	grants, err := d.grants.List(c.Request.Context(), structs.GrantFilter{Limit: constants.MaxPageLimit})
	if err != nil {
		return nil, err
	}
	g, err := d.graph.Build(c.Request.Context())
	if err != nil {
		return nil, err
	}
	calls := make(map[uint64]uint64, len(g.Edges))
	for _, e := range g.Edges {
		calls[e.GrantID] = e.Calls
	}

	out := make([]grantRow, 0, len(grants))
	for i := range grants {
		out = append(out, toGrantRow(&grants[i], calls, user))
	}
	return out, nil
}
