package caddyjwt

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	jwt "github.com/dgrijalva/jwt-go"
)

func init() {
	caddy.RegisterModule(Middleware{
		Redirect:          "/login",
		TokenSourceHeader: "jwt_token",
		TokenSourceCookie: "jwt_token",
		TokenSourceBearer: true,
	})
	httpcaddyfile.RegisterHandlerDirective("jwt", parseCaddyfile)
}

type Middleware struct {
	Secret            string
	Path              string
	Except            string
	TokenSourceHeader string
	TokenSourceCookie string
	TokenSourceBearer bool
	Redirect          string
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.jwt",
		New: func() caddy.Module {
			return new(Middleware)
		},
	}
}

func (m *Middleware) ValidateToken(uToken string) (*jwt.Token, error) {
	if len(uToken) == 0 {
		return nil, fmt.Errorf("Token length is zero")
	}

	token, err := jwt.Parse(uToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(m.Secret), nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}

func (m *Middleware) ExtractToken(r *http.Request) (string, error) {

	if m.TokenSourceBearer {
		jwtHeader := strings.Split(r.Header.Get("Authorization"), " ")
		if len(jwtHeader) == 2 && jwtHeader[0] == "Bearer" {
			return jwtHeader[1], nil
		}
	}

	if m.TokenSourceHeader != "" {
		header := r.Header.Get(m.TokenSourceHeader)
		if header != "" {
			return header, nil
		}
	}

	if m.TokenSourceCookie != "" {
		jwtCookie, err := r.Cookie(m.TokenSourceCookie)
		if err == nil {
			return jwtCookie.Value, nil
		}
	}

	return "", fmt.Errorf("no token found")
}

// Provision implements caddy.Provisioner.
func (m *Middleware) Provision(ctx caddy.Context) error {
	return nil
}

// Validate implements caddy.Validator.
func (m *Middleware) Validate() error {
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	token, _ := m.ExtractToken(r)

	if strings.HasPrefix(r.URL.EscapedPath(), m.Path) && !strings.HasPrefix(r.URL.EscapedPath(), m.Except) {
		if _, error := m.ValidateToken(token); error != nil {
			w.Header().Add("location", m.Redirect)
			w.WriteHeader(http.StatusTemporaryRedirect)
			w.Write([]byte(m.Redirect))
			return nil
		}
	}

	return next.ServeHTTP(w, r)

}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			if d.Token().Text == "secret" {
				d.Args(&m.Secret)
			} else if d.Token().Text == "token_source_header" {
				d.Args(&m.TokenSourceHeader)
			} else if d.Token().Text == "token_source_cookie" {
				d.Args(&m.TokenSourceCookie)
			} else if d.Token().Text == "path" {
				d.Args(&m.Path)
			} else if d.Token().Text == "except" {
				d.Args(&m.Except)
			} else if d.Token().Text == "redirect" {
				d.Args(&m.Redirect)
			} else {
				return d.SyntaxErr("Unexpected token: " + d.Token().Text)
			}
		}
	}2015

	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {

	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
