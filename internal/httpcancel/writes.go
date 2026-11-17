// Package httpcancel interrupts a protected response when its work is revoked.
package httpcancel

import (
	"context"
	"net/http"
	"time"
)

// Writes interrupts blocked network writes, not just cooperative request work.
// Release waits for its callback before resetting the per-response deadline so
// it cannot expire a later request on a reused HTTP/1 connection.
func Writes(ctx context.Context, w http.ResponseWriter) func() {
	controller := http.NewResponseController(w)
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = controller.SetWriteDeadline(time.Now())
		close(done)
	})
	return func() {
		if !stop() {
			<-done
			_ = controller.SetWriteDeadline(time.Time{})
		}
	}
}
