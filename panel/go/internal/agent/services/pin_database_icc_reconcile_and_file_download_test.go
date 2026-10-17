package services

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/moby/moby/client"
)

// database-icc-reconcile-and-file-download-pin-e2e.sh D1: the ICC reconcile
// tears the network down first, so a reconnect failure must NOT abort the loop
// — every container after the bad one still has to be reattached, and the
// error must name exactly the ones that were not. Driven against a fake Docker
// API on loopback (the Rust suite's live-Docker test, made hermetic).
func TestPinDatabaseIccReconcileReconnectsEveryContainerDespiteOneBadID(t *testing.T) {
	var mu sync.Mutex
	var connected []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/disconnect"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && strings.Contains(p, "/networks/"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(p, "/networks/create"):
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"Id":"n1","Warning":""}`)
		case strings.HasSuffix(p, "/connect"):
			var body struct{ Container string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Container == "bad" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"message":"No such container: bad"}`)
				return
			}
			mu.Lock()
			connected = append(connected, body.Container)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected docker call %s %s", r.Method, p)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	docker, err := client.New(client.WithHost("tcp://"+strings.TrimPrefix(srv.URL, "http://")), client.WithAPIVersion("1.47"))
	if err != nil {
		t.Fatal(err)
	}
	defer docker.Close()

	err = databaseReconcileNetworkIccAt(context.Background(), docker, "pin-icc-net", []string{"first", "bad", "last"})
	if err == nil {
		t.Fatal("a failed reconnect was reported as success")
	}
	if !strings.Contains(err.Error(), "bad") || strings.Contains(err.Error(), "first") || strings.Contains(err.Error(), "last") {
		t.Fatalf("the error must name exactly the failed container: %v", err)
	}
	if len(connected) != 2 || connected[0] != "first" || connected[1] != "last" {
		t.Fatalf("the loop aborted on the first failure — reconnected %v, want [first last]", connected)
	}
}
