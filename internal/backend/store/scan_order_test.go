package store

import "testing"

func TestScanNewerUsesInstallationEpoch(t *testing.T) {
	cases := []struct {
		name                           string
		epoch, seq, lastEpoch, lastSeq int64
		want                           bool
	}{
		{"new epoch restarts sequence", 1, 1, 0, 50, true},
		{"same epoch newer sequence", 1, 2, 1, 1, true},
		{"same epoch equal sequence", 1, 1, 1, 1, false},
		{"same epoch older sequence", 1, 1, 1, 2, false},
		{"older epoch is stale", 0, 100, 1, 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanNewer(tc.epoch, tc.seq, tc.lastEpoch, tc.lastSeq); got != tc.want {
				t.Fatalf("scanNewer(%d,%d,%d,%d) = %v, want %v", tc.epoch, tc.seq, tc.lastEpoch, tc.lastSeq, got, tc.want)
			}
		})
	}
}
