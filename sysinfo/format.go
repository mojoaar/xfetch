// Package sysinfo - Formatting utilities
package sysinfo

import (
	"fmt"
	"strings"
)

// FormatBytes converts a byte count to a human-readable string with appropriate units.
//
// Parameters:
//   - bytes: The number of bytes to format
//
// Returns:
//   - A formatted string with the most appropriate unit (B, KB, MB, GB, TB)
//
// Example: FormatBytes(1536) returns "1.5 KB"
func FormatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"KB", "MB", "GB", "TB", "PB"}
	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), units[exp])
}

// TruncateString truncates a string to a maximum length and adds ellipsis if needed.
//
// Parameters:
//   - s: The string to truncate
//   - maxLen: Maximum length of the resulting string
//
// Returns:
//   - The original string if it's shorter than maxLen
//   - A truncated string with "..." appended if longer than maxLen
//
// Example: TruncateString("Hello World", 8) returns "Hello..."
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// PadRight pads a string with spaces to reach a minimum width.
//
// Parameters:
//   - s: The string to pad
//   - width: The desired minimum width
//
// Returns:
//   - The padded string
//
// Example: PadRight("Hi", 5) returns "Hi   "
func PadRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}
