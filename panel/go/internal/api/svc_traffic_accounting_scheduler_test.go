package api

import (
	"testing"
	"time"
)

func TestTrafficAccountingSchedulerMonthKeyFormatsAsYearDashMonth(t *testing.T) {
	ts, _ := time.Parse(time.RFC3339, "2026-09-08T10:00:00Z")
	if k := trafficAccountingSchedulerMonthKey(ts); k != "2026-09" {
		t.Fatal(k)
	}
}

func TestTrafficAccountingSchedulerMonthKeyDistinguishesAdjacentMonths(t *testing.T) {
	aug, _ := time.Parse(time.RFC3339, "2026-08-31T23:59:59Z")
	sep, _ := time.Parse(time.RFC3339, "2026-09-01T00:00:01Z")
	if trafficAccountingSchedulerMonthKey(aug) == trafficAccountingSchedulerMonthKey(sep) {
		t.Fatal("adjacent months collide")
	}
}
