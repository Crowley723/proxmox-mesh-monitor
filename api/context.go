package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Crowley723/proxmox-node-monitor/config"
)

type AppContext struct {
	context.Context
	Config   *config.Config
	Logger   *slog.Logger
	Request  *http.Request
	Response http.ResponseWriter
}

type contextKey string

const appContextKey contextKey = "appContext"

// AppHandler is a handler that takes only AppContext
type AppHandler func(*AppContext)

// AppContextMiddleware injects AppContext into the request context
func AppContextMiddleware(baseCtx *AppContext) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCtx := &AppContext{
				Context:  r.Context(),
				Config:   baseCtx.Config,
				Logger:   baseCtx.Logger,
				Request:  r,
				Response: w,
			}
			ctx := context.WithValue(r.Context(), appContextKey, requestCtx)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Wrap converts an AppHandler to http.HandlerFunc
func Wrap(handler AppHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		appCtx := GetAppContext(r)
		if appCtx == nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		handler(appCtx)
	}
}

// RequireMTLS wraps a handler requiring mutual TLS
func RequireMTLS(caCertPool *x509.CertPool, handler AppHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		appCtx := GetAppContext(r)
		if appCtx == nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Check if client certificate exists and is valid
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "Client certificate required", http.StatusUnauthorized)
			return
		}

		handler(appCtx)
	}
}

// NewAppContext creates a new AppContext
func NewAppContext(ctx context.Context, cfg *config.Config, logger *slog.Logger) *AppContext {
	return &AppContext{
		Context: ctx,
		Config:  cfg,
		Logger:  logger,
	}
}

// GetAppContext retrieves AppContext from request
func GetAppContext(r *http.Request) *AppContext {
	if ctx, ok := r.Context().Value(appContextKey).(*AppContext); ok {
		return ctx
	}
	return nil
}

// Methods on AppContext for responses
func (ctx *AppContext) WriteJSON(status int, data interface{}) {
	ctx.Response.Header().Set("Content-Type", "application/json")
	ctx.Response.WriteHeader(status)
	if err := json.NewEncoder(ctx.Response).Encode(data); err != nil {
		ctx.Logger.Error("failed to encode json", "error", err)
	}
}

func (ctx *AppContext) WriteText(status int, text string) {
	ctx.Response.WriteHeader(status)
	if _, err := ctx.Response.Write([]byte(text)); err != nil {
		ctx.Logger.Error("failed to write text", "error", err)
	}
}

func (ctx *AppContext) SetJSONError(status int, message string) {
	ctx.WriteJSON(status, map[string]string{
		"error": message,
	})
}

func (ctx *AppContext) SetJSONStatus(status int, message string) {
	ctx.WriteJSON(status, map[string]string{
		"status": message,
	})
}

func (ctx *AppContext) Redirect(url string, status int) {
	http.Redirect(ctx.Response, ctx.Request, url, status)
}

func (ctx *AppContext) WriteBytes(status int, contentType string, bytes []byte) {
	ctx.Response.Header().Set("Content-Type", contentType)
	ctx.Response.WriteHeader(status)
	if _, err := ctx.Response.Write(bytes); err != nil {
		ctx.Logger.Error("failed to write response", "err", err)
	}
}
