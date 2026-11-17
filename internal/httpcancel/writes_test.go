package httpcancel

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCancellationInterruptsAnActualBlockedResponseWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		release := Writes(ctx, w)
		defer release()
		w.WriteHeader(200)
		_ = http.NewResponseController(w).Flush()
		chunk := make([]byte, 8<<20)
		for {
			if _, err := w.Write(chunk); err != nil {
				finished <- err
				return
			}
		}
	}))
	defer server.Close()
	response, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	// Leave the body unread: the native ResponseWriter eventually blocks even
	// though the request handler itself does not inspect the revoked context.
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("revoked output continued")
		}
	case <-time.After(time.Second):
		t.Fatal("revoked response remained blocked in its socket write")
	}
}

func TestReleasedResponseDoesNotInheritALaterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		release := Writes(ctx, w)
		release()
		cancel()
		_, _ = io.WriteString(w, "released")
	}))
	defer server.Close()
	response, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil || string(content) != "released" {
		t.Fatal("released response expired", err)
	}
}
