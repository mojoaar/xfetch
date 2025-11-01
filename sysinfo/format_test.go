package sysinfo

import "testing"

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		in         uint64
		wantPrefix string
	}{
		{512, "512 B"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
	}

	for _, tc := range tests {
		got := FormatBytes(tc.in)
		if len(got) == 0 || got[:len(tc.wantPrefix)] != tc.wantPrefix {
			t.Fatalf("FormatBytes(%d) = %q; want prefix %q", tc.in, got, tc.wantPrefix)
		}
	}
}

func TestTruncateString(t *testing.T) {
	if got := TruncateString("Hello World", 8); got != "Hello..." {
		t.Fatalf("TruncateString short failed: got %q", got)
	}
	if got := TruncateString("Hi", 5); got != "Hi" {
		t.Fatalf("TruncateString no-truncate failed: got %q", got)
	}
}

func TestPadRight(t *testing.T) {
	if got := PadRight("Hi", 5); got != "Hi   " {
		t.Fatalf("PadRight failed: got %q", got)
	}
	if got := PadRight("HelloWorld", 5); got != "HelloWorld" {
		t.Fatalf("PadRight truncate-case failed: got %q", got)
	}
}
