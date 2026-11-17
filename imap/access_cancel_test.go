package imap

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestCancelledSetupClosesWireDuringGreeting(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := newClientConnection(ctx, client, "eval@example.test", "owned-fixture-password")
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled setup admitted a client")
		}
	case <-time.After(time.Second):
		t.Fatal("greeting ignored cancellation")
	}
}
func TestCancelledSetupClosesWireDuringLogin(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := newClientConnection(ctx, client, "eval@example.test", "owned-fixture-password")
		done <- err
	}()
	_, err := server.Write([]byte("* OK [CAPABILITY IMAP4rev1] owned server ready\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Login begins on the real protocol client, then cancellation interrupts it.
	command := make([]byte, 4096)
	server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = server.Read(command); err != nil {
		t.Fatal("login did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled login admitted a client")
		}
	case <-time.After(time.Second):
		t.Fatal("login ignored cancellation")
	}
}
