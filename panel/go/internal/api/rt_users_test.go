package api

import (
	"slices"

	"github.com/google/uuid"
	"strings"
	"testing"
)

// The list and the sentence describing it are two facts that must agree;
// adding a role to the list and forgetting the message would tell an operator
// their valid role is invalid.
func TestRtUsersRoleMessageNamesEveryAssignableRole(t *testing.T) {
	for _, role := range AssignableRoles {
		if !strings.Contains(rtUsersAssignableRolesMsg, role) {
			t.Fatalf("role %q is assignable but the error message does not name it", role)
		}
	}
}

// It is reached through toggle_suspend, which also stashes the previous role.
func TestRtUsersSuspendedIsNotDirectlyAssignable(t *testing.T) {
	if slices.Contains(AssignableRoles[:], "suspended") {
		t.Fatal()
	}
}

// s312 / GitHub #51: `client` is assignable at all. The restore arms live
// beside suspendAccount/unsuspendAccount (core_helpers_test.go).
func TestRtUsersTheClientRoleIsAssignable(t *testing.T) {
	if !slices.Contains(AssignableRoles[:], "client") {
		t.Fatal()
	}
}

func TestRtUsersIsOtherAdmin(t *testing.T) {
	me, other := uuid.New(), uuid.New()
	if !rtUsersIsOtherAdmin("admin", other, me) || rtUsersIsOtherAdmin("admin", me, me) || rtUsersIsOtherAdmin("user", other, me) {
		t.Fatal()
	}
}
