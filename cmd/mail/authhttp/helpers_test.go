package authhttp

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/olegpustovit/mcp-icloud-email/internal/components/auth"
)

// testService opens an auth service on a disposable mail_test_* database and drops it afterwards.
// The production database name "mail" is never used by tests.
func testService(t *testing.T, uri string) *auth.Service {
	t.Helper()
	ctx := context.Background()
	name := "mail_test_" + auth.Hash(auth.Random())[:12]
	s, err := auth.New(ctx, auth.Config{BaseURL: "https://mail.example.com", MongoURI: uri, Database: name, EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = s.Close(c)
		var client *mongo.Client
		if client, err = mongo.Connect(options.Client().ApplyURI(uri)); err == nil {
			_ = client.Database(name).Drop(c)
			_ = client.Disconnect(c)
		}
	})
	return s
}
