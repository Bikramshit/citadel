package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"citadel/internal/value"
)

// maxRequestBody bounds every request body the servers read.
const maxRequestBody = 64 << 10

// listenLoopback listens on addr, which must be on 127.0.0.1.
func listenLoopback(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		return nil, fmt.Errorf("%w: listen address %q must be 127.0.0.1:port", value.ErrConfig, addr)
	}
	return net.Listen("tcp", addr)
}

// recoverer turns a handler panic into a 500 with no stack trace.
func recoverer(log *slog.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				log.Error("handler panic", "path", r.URL.Path, "panic", value.Truncate(fmt.Sprint(p)))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		h.ServeHTTP(w, r)
	})
}

// serve runs h on ln until ctx is cancelled, then shuts down gracefully.
func serve(ctx context.Context, log *slog.Logger, ln net.Listener, h http.Handler, writeTimeout time.Duration) error {
	srv := &http.Server{
		Handler:           recoverer(log, h),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	log.Info("listening", "addr", ln.Addr().String())
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		log.Info("shutting down")
		return srv.Shutdown(sctx)
	}
}

// readJSON strictly decodes a bounded request body.
func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
	if err != nil {
		return fmt.Errorf("%w: request body: %v", value.ErrSize, err)
	}
	return value.DecodeStrict(b, v, value.Limits{MaxBytes: maxRequestBody})
}

// writeJSON writes v with status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError reports err with its specification code.
func writeError(w http.ResponseWriter, status int, err error) {
	code := value.CodeOf(err)
	if code == "" {
		code = "ERR_REQUEST"
	}
	writeJSON(w, status, map[string]string{"error": code, "detail": value.Truncate(err.Error())})
}

// sse streams events to a client until it disconnects.
func sse(w http.ResponseWriter, r *http.Request, ch <-chan any) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(e)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		case <-tick.C:
			fmt.Fprint(w, ": keep-alive\n\n")
			fl.Flush()
		}
	}
}
