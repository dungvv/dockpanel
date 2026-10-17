package services

import "testing"

// backup-lands §3 (D): success is an explicit 2xx. A 3xx (wrong-region bucket)
// transfers nothing and curl exits 0, so it must never read as delivered.
func TestPinBackupLandsS3OkIsExactly2xx(t *testing.T) {
	for code, want := range map[int]bool{0: false, 199: false, 200: true, 204: true, 299: true, 301: false, 307: false, 403: false, 500: false} {
		if got := remoteBackupS3Ok(code); got != want {
			t.Errorf("remoteBackupS3Ok(%d) = %v, want %v", code, got, want)
		}
	}
}
