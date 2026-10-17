package api

import (
	"testing"

	"github.com/google/uuid"
)

// container-ownership-pin-e2e.sh D1: a missing or malformed owner label is
// excluded from every user's count, never folded into some shared bucket.
func TestPinContainerOwnershipOwnerFailsClosed(t *testing.T) {
	me, other := uuid.New(), uuid.New()
	apps := []any{
		map[string]any{"user_id": me.String()},
		map[string]any{"user_id": me.String()},
		map[string]any{"user_id": other.String()},
		map[string]any{"user_id": "not-a-uuid"},
		map[string]any{"user_id": ""},
		map[string]any{"name": "legacy, no label"},
		"garbage",
	}
	for i, a := range apps[3:] {
		if rtDockerAppsAppOwner(a) != nil {
			t.Errorf("case %d: an unowned app was attributed", i)
		}
	}
	if o := rtDockerAppsAppOwner(apps[0]); o == nil || *o != me {
		t.Fatal("a well-formed owner was not read")
	}
	if n := rtDockerAppsCountOwnedBy(apps, me); n != 2 {
		t.Fatalf("CountOwnedBy(me) = %d, want 2", n)
	}
	if n := rtDockerAppsCountOwnedBy(apps, uuid.Nil); n != 0 {
		t.Fatalf("CountOwnedBy(nil uuid) = %d — unowned apps leaked into a bucket", n)
	}
	if rtDockerAppsCountOwnedBy("not an array", me) != 0 {
		t.Fatal()
	}
}
