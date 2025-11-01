// Package main provides the xfetch command-line tool for displaying Windows system information
// with ASCII art logos that vary based on the operating system edition.
package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"

	"github.com/mattn/go-runewidth"

	"xfetch/ascii"
	"xfetch/sysinfo"
)

// gapSize controls number of spaces between logo and info. Set by flag in main().
var gapSize = 4

// ansiRegex matches ANSI escape codes for removal/measurement purposes
var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// main is the entry point for the xfetch application.
// It retrieves system information, selects appropriate ASCII art,
// and displays them side-by-side in the terminal.
func main() {
	// CLI flags
	compact := flag.Bool("compact", false, "use compact alternative ASCII logo")
	gap := flag.Int("gap", 4, "number of spaces between logo and info")
	noWAN := flag.Bool("no-wan", false, "disable public WAN IP lookup")
	debug := flag.Bool("debug", false, "enable debug output (sets XFETCH_DEBUG)")
	flag.Parse()

	gapSize = *gap
	if *debug {
		_ = os.Setenv("XFETCH_DEBUG", "1")
	}
	if *noWAN {
		_ = os.Setenv("XFETCH_NO_WAN", "1")
	}
	// Retrieve comprehensive system information
	info, err := sysinfo.GetSystemInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting system info: %v\n", err)
		os.Exit(1)
	}

	// Select ASCII art based on OS type (Server vs Client) or compact flag.
	var logo []string
	if *compact {
		logo = ascii.GetAlternativeWindowsLogo()
	} else {
		logo = ascii.GetLogo(info.IsServer)
	}

	// Display the formatted output
	displayInfo(logo, info)
}

// displayInfo renders the ASCII art logo and system information side-by-side.
//
// Parameters:
//   - logo: Slice of strings representing the ASCII art, one string per line
//   - info: Pointer to SystemInfo struct containing all system details
//
// The function combines the logo and info lines, ensuring proper alignment
// and color formatting for an aesthetically pleasing terminal output.
func displayInfo(logo []string, info *sysinfo.SystemInfo) {
	// Generate formatted information lines
	userColored := colorize(info.Username, sysinfo.ColorCyan)
	hostColored := colorize(info.Hostname, sysinfo.ColorCyan)
	// Use visible width (stripping ANSI) to compute separator length so colors don't break alignment
	sepLen := getVisibleWidth(userColored) + getVisibleWidth(hostColored) + 1
	// Choose an appropriate label for the kernel/build field. On Windows it's more
	// user-friendly to show "OS Build" rather than "Kernel".
	kernelLabel := "Kernel"
	if runtime.GOOS == "windows" {
		kernelLabel = "OS Build"
	}

	// Replace empty network fields with a user-friendly "Unknown" label
	localIP := info.LocalIP
	if strings.TrimSpace(localIP) == "" {
		localIP = "Unknown"
	}
	wanIP := info.WANIP
	if strings.TrimSpace(wanIP) == "" {
		wanIP = "Unknown"
	}

	infoLines := []string{
		"",
		fmt.Sprintf("%s@%s", userColored, hostColored),
		strings.Repeat("-", sepLen),
		fmt.Sprintf("%s: %s", colorize("OS", sysinfo.ColorBlue), info.OS),
		fmt.Sprintf("%s: %s", colorize("Host", sysinfo.ColorBlue), info.Host),
		fmt.Sprintf("%s: %s", colorize("Local IP", sysinfo.ColorBlue), localIP),
		fmt.Sprintf("%s: %s", colorize("WAN IP", sysinfo.ColorBlue), wanIP),
		fmt.Sprintf("%s: %s", colorize(kernelLabel, sysinfo.ColorBlue), info.Kernel),
		fmt.Sprintf("%s: %s", colorize("Uptime", sysinfo.ColorBlue), info.Uptime),
		fmt.Sprintf("%s: %s", colorize("Packages", sysinfo.ColorBlue), info.Packages),
		fmt.Sprintf("%s: %s", colorize("Shell", sysinfo.ColorBlue), info.Shell),
		fmt.Sprintf("%s: %s", colorize("Resolution", sysinfo.ColorBlue), info.Resolution),
		fmt.Sprintf("%s: %s", colorize("Terminal", sysinfo.ColorBlue), info.Terminal),
		fmt.Sprintf("%s: %s", colorize("CPU", sysinfo.ColorBlue), info.CPU),
		fmt.Sprintf("%s: %s", colorize("GPU", sysinfo.ColorBlue), info.GPU),
		fmt.Sprintf("%s: %s", colorize("Memory", sysinfo.ColorBlue), info.Memory),
		fmt.Sprintf("%s: %s", colorize("Disk", sysinfo.ColorBlue), info.Disk),
		"",
		colorBar(),
		"",
	}

	// Top-align logo and info: print from the top line downward. This keeps
	// ASCII art anchored at the top and prevents shifting when info lines
	// change length.
	// Calculate logo width for proper spacing (excluding ANSI codes)
	logoWidth := 0
	for _, line := range logo {
		visibleWidth := getVisibleWidth(line)
		if visibleWidth > logoWidth {
			logoWidth = visibleWidth
		}
	}

	maxLines := len(logo)
	if len(infoLines) > maxLines {
		maxLines = len(infoLines)
	}

	for i := 0; i < maxLines; i++ {
		var logoLine, infoLine string

		if i < len(logo) {
			logoLine = logo[i]
			visibleWidth := getVisibleWidth(logoLine)
			paddingNeeded := logoWidth - visibleWidth
			if paddingNeeded > 0 {
				logoLine += strings.Repeat(" ", paddingNeeded)
			}
		} else {
			logoLine = strings.Repeat(" ", logoWidth)
		}

		if i < len(infoLines) {
			infoLine = infoLines[i]
		} else {
			infoLine = ""
		}

		// Use gapSize spaces between logo and info for readability
		gap := strings.Repeat(" ", gapSize)
		fmt.Printf("%s%s%s\n", logoLine, gap, infoLine)
	}
}

// getVisibleWidth calculates the visible width of a string excluding ANSI escape codes.
//
// Parameters:
//   - s: The string to measure (may contain ANSI color codes)
//
// Returns:
//   - The number of visible characters (excluding ANSI escape sequences)
//
// This is essential for proper alignment when strings contain color codes.
func getVisibleWidth(s string) int {
	// Remove all ANSI escape sequences
	stripped := ansiRegex.ReplaceAllString(s, "")
	// Use runewidth to count display width (handles wide runes)
	return runewidth.StringWidth(stripped)
}

// colorize wraps text with ANSI color codes for terminal output.
//
// Parameters:
//   - text: The string to be colorized
//   - color: ANSI color code (e.g., "\033[36m" for cyan)
//
// Returns:
//   - A string with ANSI color codes applied, followed by a reset code
func colorize(text, color string) string {
	return color + text + sysinfo.ColorReset
}

// colorBar generates a visual representation of available terminal colors.
//
// Returns:
//   - A string containing colored blocks representing the 16 basic terminal colors
//
// This provides a visual reference similar to other fetch utilities.
func colorBar() string {
	// Show the 16 basic background colors: 40-47 (standard) and 100-107 (bright)
	colors := []string{}
	for bg := 40; bg <= 47; bg++ {
		colors = append(colors, fmt.Sprintf("\033[%dm   ", bg))
	}
	for bg := 100; bg <= 107; bg++ {
		colors = append(colors, fmt.Sprintf("\033[%dm   ", bg))
	}

	bar := ""
	for _, color := range colors {
		bar += color
	}
	bar += sysinfo.ColorReset

	return bar
}
