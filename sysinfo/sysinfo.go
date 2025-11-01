// Package sysinfo provides cross-platform system information retrieval capabilities.
// It defines the core data structures and interfaces for gathering OS, hardware,
// and runtime information.
package sysinfo

// ANSI color codes for terminal output formatting
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

// SystemInfo represents comprehensive system information including
// operating system details, hardware specifications, and runtime environment.
type SystemInfo struct {
	// Username is the current logged-in user's name
	Username string

	// Hostname is the computer's network name
	Hostname string

	// OS is the full operating system name and version
	OS string

	// Host is the computer manufacturer and model
	Host string

	// Kernel is the operating system kernel version
	Kernel string

	// Uptime is the formatted system uptime duration
	Uptime string

	// Packages is the count of installed packages/applications
	Packages string

	// Shell is the current command shell being used
	Shell string

	// Resolution is the primary display resolution
	Resolution string

	// Terminal is the terminal emulator being used
	Terminal string

	// CPU is the processor model and core count
	CPU string

	// GPU is the graphics processor model
	GPU string

	// Memory shows used/total RAM
	Memory string

	// Disk shows used/total disk space for system drive
	Disk string

	// IsServer indicates whether the OS is a Server edition
	IsServer bool

	// LocalIP is the primary local IPv4 address detected for the host
	LocalIP string

	// WANIP is the public/external IP address (may require a short HTTP request)
	WANIP string
}

// GetSystemInfo retrieves comprehensive system information.
// This is the main entry point for gathering all system details.
//
// Returns:
//   - A pointer to a populated SystemInfo struct
//   - An error if critical system information cannot be retrieved
//
// Platform-specific implementations are in separate files (e.g., windows.go).
func GetSystemInfo() (*SystemInfo, error) {
	return getSystemInfoWindows()
}
