package logging

import (
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

// LevelHandler returns an http.HandlerFunc for runtime level inspection and
// change, intended to be mounted on the existing metrics/admin listener.
//
//	GET  -> returns the current level as text (e.g. "INFO")
//	PUT/POST ?level=debug -> sets the level; returns the new level
//
// This lets an operator drop one hot host to debug without a restart.
func LevelHandler(lvl *slog.LevelVar) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(lvl.Level().String()))
		case http.MethodPut, http.MethodPost:
			q := r.URL.Query().Get("level")
			if q == "" {
				http.Error(w, "missing level query parameter", http.StatusBadRequest)
				return
			}
			lvl.Set(ParseLevel(q))
			slog.Info("log level changed", "level", lvl.Level().String())
			_, _ = w.Write([]byte(lvl.Level().String()))
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// InstallSIGHUPToggle wires SIGHUP to toggle between base and slog.LevelDebug.
// The first SIGHUP enables debug; the next restores base, and so on. It returns
// a stop func that unregisters the handler. base is typically the configured
// startup level.
func InstallSIGHUPToggle(lvl *slog.LevelVar, base slog.Level) (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				if lvl.Level() == slog.LevelDebug {
					lvl.Set(base)
				} else {
					lvl.Set(slog.LevelDebug)
				}
				slog.Info("log level toggled via SIGHUP", "level", lvl.Level().String())
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}
