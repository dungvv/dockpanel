package api

import "testing"

func TestNotificationsSeverityColorCriticalIsRed(t *testing.T) {
	if got := NotificationsSeverityColor("critical"); got != "#ef4444" {
		t.Fatal(got)
	}
}

func TestNotificationsSeverityColorWarningIsAmber(t *testing.T) {
	if got := NotificationsSeverityColor("warning"); got != "#f59e0b" {
		t.Fatal(got)
	}
}

// info and any unrecognised value fall to the same blue — an unknown string
// degrades to what "no severity" always meant.
func TestNotificationsSeverityColorInfoAndAnythingUnrecognisedIsBlue(t *testing.T) {
	for _, s := range []string{"info", "bogus", ""} {
		if got := NotificationsSeverityColor(s); got != "#3b82f6" {
			t.Errorf("%q → %s", s, got)
		}
	}
}

func TestNotificationsASuccessClearsTheThreeThatSayNoRenewalHappened(t *testing.T) {
	for _, k := range []string{NotificationsSslRenewalKeyFailed, NotificationsSslRenewalKeyBlocked, NotificationsSslRenewalKeyDns01Declined} {
		if !NotificationsRenewalSuccessClears(k) {
			t.Errorf("%s must be cleared", k)
		}
	}
}

// DNS01_DOWNGRADED is also RAISED on the success path, and FireAlertDeduped
// windows on created_at regardless of status — resolving it would swallow its
// own re-fire. DECLINED and MAIL_HOST_CONFLICT stay true after a renewal.
func TestNotificationsASuccessDoesNotClearTheThreeStandingConditions(t *testing.T) {
	for _, k := range []string{NotificationsSslRenewalKeyDns01Downgraded, NotificationsSslRenewalKeyDeclined, NotificationsSslRenewalKeyMailHostConflict} {
		if NotificationsRenewalSuccessClears(k) {
			t.Errorf("%s must not be cleared", k)
		}
	}
}

// Both directions at once: widening fails as loudly as narrowing.
func TestNotificationsExactlyThreeOfTheSixAreCleared(t *testing.T) {
	n := 0
	for _, k := range NotificationsSslRenewalKeyAll {
		if NotificationsRenewalSuccessClears(k) {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("keys cleared by a successful renewal: %d", n)
	}
}

// The fall-through must stay false: a later key is not resolved until
// somebody decides it should be.
func TestNotificationsAnUnrecognisedKeyIsLeftAlone(t *testing.T) {
	if NotificationsRenewalSuccessClears("some_key_added_later") || NotificationsRenewalSuccessClears("") {
		t.Fatal("unknown key cleared")
	}
}

// Go-only: goldmark must pass raw HTML through like pulldown-cmark's
// push_html, and render CommonMark.
func TestNotificationsRenderRunbookHTMLMatchesPulldown(t *testing.T) {
	if got := notificationsRenderRunbookHTML("# Hi\n\n**b** <kbd>x</kbd>"); got != "<h1>Hi</h1>\n<p><strong>b</strong> <kbd>x</kbd></p>\n" {
		t.Fatalf("%q", got)
	}
}
