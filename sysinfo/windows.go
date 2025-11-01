//go:build windows
// +build windows

// Package sysinfo - Windows-specific implementation
package sysinfo

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"context"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	moduser32   = windows.NewLazySystemDLL("user32.dll")
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procGetTickCount64       = modkernel32.NewProc("GetTickCount64")
	procGlobalMemoryStatusEx = modkernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemMetrics     = moduser32.NewProc("GetSystemMetrics")
	// Inline ntdll.dll lazy DLL creation so we only keep the proc variable.
	// This avoids an unused `modntdll` variable being flagged by staticcheck
	// (U1000). If you prefer a named DLL handle for clarity or reuse, you
	// can replace this with:
	//   modntdll = windows.NewLazySystemDLL("ntdll.dll")
	//   procRtlGetVersion = modntdll.NewProc("RtlGetVersion")
	procRtlGetVersion            = windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlGetVersion")
	procCreateToolhelp32Snapshot = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = modkernel32.NewProc("Process32FirstW")
	procProcess32NextW           = modkernel32.NewProc("Process32NextW")
	procGetBestInterface         = modiphlpapi.NewProc("GetBestInterface")
)

// memoryStatusEx represents the Windows MEMORYSTATUSEX structure.
// It provides information about physical and virtual memory.
type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

// getSystemInfoWindows retrieves system information specific to Windows.
//
// Returns:
//   - A populated SystemInfo struct with Windows-specific details
//   - An error if critical system calls fail
//
// This function aggregates information from various Windows APIs and registry keys.
func getSystemInfoWindows() (*SystemInfo, error) {
	info := &SystemInfo{}

	// Get username
	info.Username = os.Getenv("USERNAME")
	if info.Username == "" {
		info.Username = "Unknown"
	}

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "Unknown"
	}
	info.Hostname = hostname

	// Get OS information
	info.OS = getWindowsVersion()
	info.IsServer = isWindowsServer()

	// Run a minimal combined PowerShell/CIM query to reduce process startups.
	// We intentionally avoid heavy queries (event log) here. Parent process is
	// retrieved using native Toolhelp APIs to avoid spawning PowerShell.
	// include BaseBoard (motherboard) to provide a more precise Host/motherboard model
	psCmd := " $cs=Get-CimInstance Win32_ComputerSystem | Select-Object -First 1 -Property Manufacturer,Model; $os=Get-CimInstance Win32_OperatingSystem | Select-Object -First 1 -Property LastBootUpTime; $proc=Get-CimInstance Win32_Processor | Select-Object -First 1 -Property Name,NumberOfCores; $vg=Get-CimInstance Win32_VideoController | Select-Object -First 1 -Property Name; $bb=Get-CimInstance Win32_BaseBoard | Select-Object -First 1 -Property Manufacturer,Product,Version; @{ComputerSystem=$cs; OS=$os; Processor=$proc; VideoController=$vg; BaseBoard=$bb; Now=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json -Compress"

	var combined struct {
		ComputerSystem struct {
			Manufacturer string
			Model        string
		}
		OS struct {
			LastBootUpTime string
		}
		Processor struct {
			Name          string
			NumberOfCores int
		}
		VideoController struct {
			Name string
		}
		BaseBoard struct {
			Manufacturer string
			Product      string
			Version      string
		}
		Now string
	}

	// Use centralized PowerShell helper with a short timeout to reduce hangs
	_, cerr := runPowerShellJSON(psCmd, 1500*time.Millisecond, &combined)
	if cerr == nil {
		if combined.ComputerSystem.Manufacturer != "" || combined.ComputerSystem.Model != "" {
			info.Host = strings.TrimSpace(combined.ComputerSystem.Manufacturer + " " + combined.ComputerSystem.Model)
		}

		// Prefer BaseBoard (motherboard) product/manufacturer if available and non-empty
		if combined.BaseBoard.Product != "" {
			bbManufacturer := strings.TrimSpace(combined.BaseBoard.Manufacturer)
			bbProduct := strings.TrimSpace(combined.BaseBoard.Product)
			if bbProduct != "" {
				if bbManufacturer != "" {
					info.Host = bbManufacturer + " " + bbProduct
				} else {
					info.Host = bbProduct
				}
			}
		}
		if combined.Processor.Name != "" {
			if combined.Processor.NumberOfCores > 0 {
				info.CPU = fmt.Sprintf("%s (%d cores)", strings.TrimSpace(combined.Processor.Name), combined.Processor.NumberOfCores)
			} else {
				info.CPU = strings.TrimSpace(combined.Processor.Name)
			}
		}
		if combined.VideoController.Name != "" {
			info.GPU = strings.TrimSpace(combined.VideoController.Name)
		}
		// Compute uptime from PS boot/now; resume-based adjustments happen in getUptime fallback.
		if combined.OS.LastBootUpTime != "" && combined.Now != "" {
			if bootTime, berr := time.Parse(time.RFC3339, combined.OS.LastBootUpTime); berr == nil {
				if nowTime, nerr := time.Parse(time.RFC3339, combined.Now); nerr == nil {
					uptime := nowTime.Sub(bootTime)
					ret, _, _ := procGetTickCount64.Call()
					var tickDur time.Duration
					if ret != 0 {
						tickDur = time.Duration(ret) * time.Millisecond
					}
					chosen := uptime
					source := "powerShell"
					if tickDur > 0 && tickDur < chosen {
						chosen = tickDur
						source = "tick"
					}
					info.Uptime = fmt.Sprintf("%s (%s)", formatUptime(chosen), source)
				}
			}
		}
	}

	// Kernel/build is cheap (registry), compute quickly. We already display
	// the OS name in the `OS` field, so show only the build number here for
	// brevity (e.g., "Build 26200").
	info.Kernel = fmt.Sprintf("Build %s", getWindowsBuildNumber())

	// Continue with other fields concurrently. Some values may already be set
	// from the combined PS query above; the goroutines below will only set
	// the field if it is still empty.
	var wg sync.WaitGroup
	var mu sync.Mutex

	// helper to set string fields safely if empty
	setField := func(field *string, val string) {
		mu.Lock()
		if *field == "" {
			*field = val
		}
		mu.Unlock()
	}

	if info.Host == "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			setField(&info.Host, getComputerModel())
		}()
	}

	if info.Uptime == "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			setField(&info.Uptime, getUptime())
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		setField(&info.Packages, getInstalledPrograms())
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		// Use native parent process lookup to decide shell without spawning PowerShell.
		pp := getParentProcessName()
		if pp != "" {
			lower := strings.ToLower(pp)
			switch {
			case strings.Contains(lower, "pwsh"):
				setField(&info.Shell, "PowerShell Core")
			case strings.Contains(lower, "powershell"):
				setField(&info.Shell, "PowerShell")
			case strings.Contains(lower, "cmd"):
				setField(&info.Shell, "cmd.exe")
			default:
				setField(&info.Shell, pp)
			}
		} else {
			setField(&info.Shell, getShell())
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		setField(&info.Resolution, getScreenResolution())
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		setField(&info.Terminal, getTerminal())
	}()

	if info.CPU == "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			setField(&info.CPU, getCPUInfo())
		}()
	}

	if info.GPU == "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			setField(&info.GPU, getGPUInfo())
		}()
	}

	// Network information: local IP and WAN (public) IP - run concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		// local
		local := getLocalIP()
		setField(&info.LocalIP, local)
		// wan: skip if explicitly disabled via env var
		if os.Getenv("XFETCH_NO_WAN") == "" {
			if hasInternetConnectivity(500 * time.Millisecond) {
				wan := getWANIP()
				setField(&info.WANIP, wan)
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		setField(&info.Memory, getMemoryInfo())
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		setField(&info.Disk, getDiskInfo())
	}()

	// Wait for all goroutines to finish
	wg.Wait()

	return info, nil
}

// getWindowsVersion retrieves the Windows product name from the registry.
//
// Returns:
//   - The full Windows product name (e.g., "Windows 11 Pro")
//   - "Windows" as fallback if registry read fails
func getWindowsVersion() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Windows"
	}
	defer func() { _ = k.Close() }()

	productName, _, err := k.GetStringValue("ProductName")
	if err != nil {
		return "Windows"
	}

	displayVersion, _, derr := k.GetStringValue("DisplayVersion")

	// Prefer RtlGetVersion for accurate OS build/major/minor values. If it succeeds,
	// use it as a source of truth for build number to disambiguate Windows 10 vs 11.
	if maj, mnr, build, rerr := rtlGetVersion(); rerr == nil {
		// If the product name mentions Windows 10 but build >= 22000 then treat as Windows 11
		if build >= 22000 && strings.Contains(strings.ToLower(productName), "windows 10") {
			productName = strings.Replace(productName, "Windows 10", "Windows 11", 1)
		}
		if derr == nil && displayVersion != "" {
			return fmt.Sprintf("%s %s", productName, displayVersion)
		}
		// Otherwise append major/minor/build for clarity
		return fmt.Sprintf("%s (Build %d, %d.%d)", productName, build, maj, mnr)
	}

	// Fallback: use registry values as before
	buildStr, _, _ := k.GetStringValue("CurrentBuild")
	if buildStr == "" {
		// fallback to other key
		buildStr = getWindowsBuildNumber()
	}
	buildNum := 0
	if buildStr != "" {
		if n, err := strconv.Atoi(buildStr); err == nil {
			buildNum = n
		}
	}

	if buildNum >= 22000 && strings.Contains(strings.ToLower(productName), "windows 10") {
		productName = strings.Replace(productName, "Windows 10", "Windows 11", 1)
	}

	if derr == nil && displayVersion != "" {
		return fmt.Sprintf("%s %s", productName, displayVersion)
	}

	return productName
}

// isWindowsServer determines if the current OS is a Windows Server edition.
//
// Returns:
//   - true if the OS is Windows Server, false otherwise
//
// Detection is based on the ProductName registry value containing "Server".
func isWindowsServer() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer func() { _ = k.Close() }()

	productName, _, err := k.GetStringValue("ProductName")
	if err != nil {
		return false
	}

	return strings.Contains(strings.ToLower(productName), "server")
}

// getWindowsBuildNumber retrieves the current Windows build number.
//
// Returns:
//   - The build number as a string (e.g., "22621")
//   - "Unknown" if registry read fails
func getWindowsBuildNumber() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Unknown"
	}
	defer func() { _ = k.Close() }()

	build, _, err := k.GetStringValue("CurrentBuild")
	if err != nil {
		return "Unknown"
	}

	return build
}

// getComputerModel retrieves the computer manufacturer and model.
//
// Returns:
//   - A formatted string with manufacturer and model (e.g., "Dell Inc. XPS 15")
//   - "Unknown" if all methods fail
//
// Tries multiple methods: WMIC, registry, and environment variables.
func getComputerModel() string {
	// Try PowerShell/CIM first (recommended over WMIC) and parse JSON
	psCmd := "Get-CimInstance Win32_ComputerSystem | Select-Object -First 1 -Property Manufacturer,Model | ConvertTo-Json -Compress"
	var cs struct {
		Manufacturer string
		Model        string
	}
	if _, err := runPowerShellJSON(psCmd, 1500*time.Millisecond, &cs); err == nil {
		if cs.Manufacturer != "" && cs.Model != "" {
			return strings.TrimSpace(cs.Manufacturer) + " " + strings.TrimSpace(cs.Model)
		}
		if cs.Manufacturer != "" {
			return strings.TrimSpace(cs.Manufacturer)
		}
		if cs.Model != "" {
			return strings.TrimSpace(cs.Model)
		}
	}

	// Try registry as fallback
	manufacturer := getRegistryString(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SystemInformation`, "SystemManufacturer")
	model := getRegistryString(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SystemInformation`, "SystemProductName")

	if manufacturer == "" {
		manufacturer = getRegistryString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "SystemManufacturer")
	}
	if model == "" {
		model = getRegistryString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "SystemProductName")
	}

	if manufacturer != "" && model != "" {
		return fmt.Sprintf("%s %s", manufacturer, model)
	}
	if manufacturer != "" {
		return manufacturer
	}
	if model != "" {
		return model
	}

	return "Unknown"
}

// getUptime calculates and formats the system uptime.
//
// Returns:
//   - A human-readable uptime string (e.g., "2 days, 5 hours, 30 mins")
//   - "Unknown" if all methods fail
//
// Uses WMI to get the actual boot time, which provides accurate uptime
// excluding sleep/hibernate periods.
func getUptime() string {
	// Try PowerShell/CIM (preferred) and return boot and now timestamps in UTC ISO format
	// We'll parse them in Go to avoid timezone/parsing surprises.
	psCmd := " $obj = Get-CimInstance Win32_OperatingSystem | Select-Object -First 1 -Property LastBootUpTime; @{LastBootUpTime = $obj.LastBootUpTime.ToUniversalTime().ToString('o'); Now = (Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json -Compress"
	// Use the centralized PowerShell helper with timeout
	var tstruct struct {
		LastBootUpTime string
		Now            string
	}
	if out, err := runPowerShellJSON(psCmd, 1500*time.Millisecond, &tstruct); err == nil {
		_ = out // out is already unmarshaled into tstruct by helper
		// proceed
		if tstruct.LastBootUpTime != "" && tstruct.Now != "" {
			if tstruct.LastBootUpTime != "" && tstruct.Now != "" {
				bootTime, berr := time.Parse(time.RFC3339, tstruct.LastBootUpTime)
				nowTime, nerr := time.Parse(time.RFC3339, tstruct.Now)
				if berr == nil && nerr == nil {
					// guard against negative durations
					if !nowTime.Before(bootTime) {
						// If debug is enabled, print raw values to stderr to help diagnose timezone/format issues
						if os.Getenv("XFETCH_DEBUG") != "" {
							fmt.Fprintf(os.Stderr, "xfetch debug: ps raw output: %s\n", strings.TrimSpace(string(out)))
							fmt.Fprintf(os.Stderr, "xfetch debug: parsed LastBootUpTime=%s, Now=%s\n", bootTime.Format(time.RFC3339), nowTime.Format(time.RFC3339))
							// Also show tick count fallback
							if ret, _, _ := procGetTickCount64.Call(); ret != 0 {
								tickDur := time.Duration(ret) * time.Millisecond
								fmt.Fprintf(os.Stderr, "xfetch debug: GetTickCount64 duration=%s\n", tickDur)
							}
						}
						uptime := nowTime.Sub(bootTime)
						// Compare with GetTickCount64-based duration and choose the smaller non-zero value.
						// Additionally, check the most recent resume time from the System event log
						// (Provider Microsoft-Windows-Power-Troubleshooter Id=1) and prefer uptime since
						// resume when it's smaller — this reflects the "time since last active" a user expects.
						ret, _, _ := procGetTickCount64.Call()
						var tickDur time.Duration
						if ret != 0 {
							tickDur = time.Duration(ret) * time.Millisecond
						}

						// Default chosen is PS-derived uptime
						chosen := uptime
						source := "powerShell"

						if tickDur > 0 && tickDur < chosen {
							chosen = tickDur
							source = "tick"
						}

						// Try to get the most recent resume time (Power-Troubleshooter Id=1)
						psResumeCmd := "(Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Power-Troubleshooter'; Id=1} -MaxEvents 1 | Select-Object -ExpandProperty TimeCreated).ToUniversalTime().ToString('o') | ConvertTo-Json -Compress"
						if rout, rerr := runPowerShellJSON(psResumeCmd, 1500*time.Millisecond, nil); rerr == nil {
							// rout contains a JSON string like "2025-11-01T07:54:00.0000000Z"
							var resumeStr string
							if jerr := json.Unmarshal(rout, &resumeStr); jerr == nil {
								if resumeStr != "" {
									if rt, perr := time.Parse(time.RFC3339, resumeStr); perr == nil {
										// compute uptime since resume
										resumeDur := nowTime.Sub(rt)
										if resumeDur > 0 && resumeDur < chosen {
											chosen = resumeDur
											source = "resume"
										}
									}
								}
							}
						}

						if os.Getenv("XFETCH_DEBUG") != "" {
							fmt.Fprintf(os.Stderr, "xfetch debug: ps uptime=%s, tick uptime=%s, chosen=%s (source=%s)\n", uptime, tickDur, chosen, source)
						}

						return fmt.Sprintf("%s (%s)", formatUptime(chosen), source)
					}
				}
			}
		}
	}

	// Method 3: Fallback to GetTickCount64 (less accurate on modern Windows)
	ret, _, _ := procGetTickCount64.Call()
	if ret == 0 {
		return "Unknown"
	}

	uptime := time.Duration(ret) * time.Millisecond
	return fmt.Sprintf("%s (tick)", formatUptime(uptime))
}

// formatUptime converts a duration into a human-readable uptime string.
//
// Parameters:
//   - uptime: The duration to format
//
// Returns:
//   - A formatted string (e.g., "2 days, 5 hours, 30 mins")
//
// Helper function to format uptime consistently across different detection methods.
func formatUptime(uptime time.Duration) string {
	days := int(uptime.Hours() / 24)
	hours := int(uptime.Hours()) % 24
	mins := int(uptime.Minutes()) % 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%d day%s", days, plural(days)))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%d hour%s", hours, plural(hours)))
	}
	if mins > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d min%s", mins, plural(mins)))
	}

	return strings.Join(parts, ", ")
}

// plural returns "s" if count is not 1, empty string otherwise.
// Helper function for grammatically correct pluralization.
//
// Parameters:
//   - count: The number to check
//
// Returns:
//   - "s" for plural, "" for singular
func plural(count int) string {
	if count != 1 {
		return "s"
	}
	return ""
}

// getInstalledPrograms counts installed programs from the Windows registry.
//
// Returns:
//   - A string representing the count of installed programs (e.g., "142")
//   - "Unknown" if registry enumeration fails
//
// Checks both 64-bit and 32-bit uninstall registry keys.
func getInstalledPrograms() string {
	count := 0
	paths := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}

	for _, path := range paths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		subkeys, err := k.ReadSubKeyNames(-1)
		_ = k.Close()
		if err != nil {
			continue
		}
		count += len(subkeys)
	}

	if count > 0 {
		return fmt.Sprintf("%d", count)
	}
	return "Unknown"
}

// getShell retrieves the current shell environment by detecting the parent process.
//
// Returns:
//   - The shell name with version (e.g., "PowerShell 7.5.4")
//   - Falls back to environment variable detection
//
// Properly detects both Windows PowerShell (5.x) and PowerShell Core (7.x)
// by checking the parent process name.
func getShell() string {
	// Try to get parent process name
	parentProcess := getParentProcessName()

	if parentProcess != "" {
		lowerParent := strings.ToLower(parentProcess)

		// Check for PowerShell Core (pwsh) and Windows PowerShell (powershell).
		// Try to obtain the version string; fall back to a generic name if the
		// executable isn't available or the command fails.
		if strings.Contains(lowerParent, "pwsh") {
			if v := getPowerShellVersion("pwsh"); v != "" {
				return fmt.Sprintf("PowerShell %s", v)
			}
			return "PowerShell Core"
		}

		if strings.Contains(lowerParent, "powershell") {
			if v := getPowerShellVersion("powershell"); v != "" {
				return fmt.Sprintf("PowerShell %s", v)
			}
			return "PowerShell"
		}

		// Check for CMD
		if strings.Contains(lowerParent, "cmd") {
			return "cmd.exe"
		}

		// Check for Windows Terminal
		if !strings.Contains(lowerParent, "windowsterminal") {
			// Return the parent process name if identified
			return parentProcess
		}
	}

	// Fallback to environment variable detection
	if os.Getenv("PSModulePath") != "" {
		if v := getPowerShellVersion("pwsh"); v != "" {
			return fmt.Sprintf("PowerShell %s", v)
		}
		if v := getPowerShellVersion("powershell"); v != "" {
			return fmt.Sprintf("PowerShell %s", v)
		}
		return "PowerShell"
	}

	// Check for other shells
	if shell := os.Getenv("SHELL"); shell != "" {
		return shell
	}

	// Fallback to COMSPEC
	shell := os.Getenv("COMSPEC")
	if shell == "" {
		shell = "cmd.exe"
	}
	return shell
}

// getParentProcessName retrieves the name of the parent process using the
// native Toolhelp snapshot APIs to avoid spawning PowerShell. Returns the
// executable name (e.g., "pwsh.exe") or empty string on failure.
func getParentProcessName() string {
	pid := uint32(os.Getpid())

	const TH32CS_SNAPPROCESS = 0x00000002

	type processEntry32 struct {
		dwSize              uint32
		cntUsage            uint32
		th32ProcessID       uint32
		th32DefaultHeapID   uintptr
		th32ModuleID        uint32
		cntThreads          uint32
		th32ParentProcessID uint32
		pcPriClassBase      int32
		dwFlags             uint32
		szExeFile           [260]uint16
	}

	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPPROCESS), uintptr(0))
	if snapshot == 0 || snapshot == uintptr(syscall.InvalidHandle) {
		return ""
	}
	defer func() { _ = windows.CloseHandle(windows.Handle(snapshot)) }()

	var pe processEntry32
	pe.dwSize = uint32(unsafe.Sizeof(pe))

	ret, _, _ := procProcess32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
	if ret == 0 {
		return ""
	}

	var parentID uint32
	for {
		if pe.th32ProcessID == pid {
			parentID = pe.th32ParentProcessID
			break
		}
		ret, _, _ = procProcess32NextW.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
		if ret == 0 {
			break
		}
	}

	if parentID == 0 {
		return ""
	}

	pe.dwSize = uint32(unsafe.Sizeof(pe))
	ret, _, _ = procProcess32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
	if ret == 0 {
		return ""
	}
	for {
		if pe.th32ProcessID == parentID {
			name := syscall.UTF16ToString(pe.szExeFile[:])
			return strings.TrimSpace(name)
		}
		ret, _, _ = procProcess32NextW.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
		if ret == 0 {
			break
		}
	}

	return ""
}

// getPowerShellVersion attempts to execute the given command ("pwsh" or
// "powershell") to retrieve $PSVersionTable.PSVersion.ToString(). It returns
// the version string on success or an empty string on failure.
func getPowerShellVersion(cmdName string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()

	c := exec.CommandContext(ctx, cmdName, "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()")
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := c.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// getScreenResolution retrieves the primary monitor's resolution.
//
// Returns:
//   - A formatted resolution string (e.g., "1920x1080")
//   - "Unknown" if the system call fails
//
// Uses Windows GetSystemMetrics API with SM_CXSCREEN and SM_CYSCREEN.
func getScreenResolution() string {
	const (
		SM_CXSCREEN = 0
		SM_CYSCREEN = 1
	)

	width, _, _ := procGetSystemMetrics.Call(uintptr(SM_CXSCREEN))
	height, _, _ := procGetSystemMetrics.Call(uintptr(SM_CYSCREEN))

	if width == 0 || height == 0 {
		return "Unknown"
	}

	return fmt.Sprintf("%dx%d", width, height)
}

// getTerminal attempts to identify the terminal emulator being used.

// Returns:
//   - The terminal name if identifiable (e.g., "Windows Terminal")
//   - The value of TERM environment variable as fallback
//   - "cmd.exe" if no terminal information is available
func getTerminal() string {
	// Check for Windows Terminal
	if os.Getenv("WT_SESSION") != "" {
		return "Windows Terminal"
	}

	// Check for other terminals via TERM_PROGRAM
	if term := os.Getenv("TERM_PROGRAM"); term != "" {
		return term
	}

	// Fallback to TERM environment variable
	if term := os.Getenv("TERM"); term != "" {
		return term
	}

	return "cmd.exe"
}

// getCPUInfo retrieves CPU model and core count information.
//
// Returns:
//   - A formatted string with CPU model and core count
//   - "Unknown" if all methods fail
//
// Tries multiple methods: WMIC and registry fallbacks.
func getCPUInfo() string {
	// Try PowerShell/CIM first and parse JSON
	psCmd := "Get-CimInstance Win32_Processor | Select-Object -First 1 -Property Name,NumberOfCores | ConvertTo-Json -Compress"
	var pc struct {
		Name          string
		NumberOfCores int
	}
	if _, err := runPowerShellJSON(psCmd, 1500*time.Millisecond, &pc); err == nil {
		name := strings.TrimSpace(pc.Name)
		cores := pc.NumberOfCores
		if name != "" {
			if cores > 0 {
				return fmt.Sprintf("%s (%d cores)", name, cores)
			}
			return name
		}
	}

	// Try registry as fallback
	cpuName := getRegistryString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "ProcessorNameString")
	if cpuName != "" {
		cpuName = strings.TrimSpace(cpuName)
		// Get number of logical processors
		if numCores := runtime.NumCPU(); numCores > 0 {
			return fmt.Sprintf("%s (%d cores)", cpuName, numCores)
		}
		return cpuName
	}

	return "Unknown"
}

// getGPUInfo retrieves the primary graphics adapter name.
//
// Returns:
//   - The GPU model name
//   - "Unknown" if all methods fail
//
// Tries multiple methods: WMIC, PowerShell, and registry enumeration.
func getGPUInfo() string {
	// Try PowerShell/CIM first and parse JSON
	psCmd := "Get-CimInstance Win32_VideoController | Select-Object -First 1 -Property Name | ConvertTo-Json -Compress"
	var vg struct {
		Name string
	}
	if _, err := runPowerShellJSON(psCmd, 1500*time.Millisecond, &vg); err == nil {
		gpu := strings.TrimSpace(vg.Name)
		if gpu != "" && !strings.Contains(strings.ToLower(gpu), "microsoft basic") {
			return gpu
		}
	}

	// Method 4: Enumerate registry keys for video controllers
	gpu := getGPUFromRegistry()
	if gpu != "" {
		return gpu
	}

	return "Unknown"
}

// getGPUFromRegistry enumerates video controller registry keys to find GPU information.
//
// Returns:
//   - The GPU name from registry if found
//   - Empty string if not found
//
// This function properly enumerates the video controller class registry keys.
func getGPUFromRegistry() string {
	// Open the video controller class key
	classKey := `SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}`

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, classKey, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer func() { _ = k.Close() }()

	// Enumerate subkeys (0000, 0001, etc.)
	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return ""
	}

	// Try each subkey
	for _, subkey := range subkeys {
		subkeyPath := classKey + `\` + subkey

		// Try DriverDesc first
		if gpu := getRegistryString(registry.LOCAL_MACHINE, subkeyPath, "DriverDesc"); gpu != "" {
			// Filter out Microsoft Basic Display Adapter
			if !strings.Contains(strings.ToLower(gpu), "microsoft basic") {
				return gpu
			}
		}

		// Try Device Description
		if gpu := getRegistryString(registry.LOCAL_MACHINE, subkeyPath, "Device Description"); gpu != "" {
			if !strings.Contains(strings.ToLower(gpu), "microsoft basic") {
				return gpu
			}
		}

		// Try HardwareInformation.AdapterString
		if gpu := getRegistryString(registry.LOCAL_MACHINE, subkeyPath, "HardwareInformation.AdapterString"); gpu != "" {
			if !strings.Contains(strings.ToLower(gpu), "microsoft basic") {
				return gpu
			}
		}
	}

	// Also try the Control\Video path
	videoKey := `SYSTEM\CurrentControlSet\Control\Video`
	k2, err := registry.OpenKey(registry.LOCAL_MACHINE, videoKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return ""
	}
	defer func() { _ = k2.Close() }()

	videoSubkeys, err := k2.ReadSubKeyNames(-1)
	if err != nil {
		return ""
	}

	for _, subkey := range videoSubkeys {
		// Skip the "Mappings" key
		if strings.EqualFold(subkey, "Mappings") {
			continue
		}

		// Try the 0000 subkey under each GUID
		subkeyPath := videoKey + `\` + subkey + `\0000`

		if gpu := getRegistryString(registry.LOCAL_MACHINE, subkeyPath, "DriverDesc"); gpu != "" {
			if !strings.Contains(strings.ToLower(gpu), "microsoft basic") {
				return gpu
			}
		}
	}

	return ""
}

// getMemoryInfo retrieves current memory usage statistics.
//
// Returns:
//   - A formatted string showing used/total memory (e.g., "8.2 GiB / 16.0 GiB")
//   - "Unknown" if the GlobalMemoryStatusEx call fails
//
// Uses Windows GlobalMemoryStatusEx API for accurate memory statistics.
func getMemoryInfo() string {
	var memInfo memoryStatusEx
	memInfo.dwLength = uint32(unsafe.Sizeof(memInfo))

	ret, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memInfo)))
	if ret == 0 {
		return "Unknown"
	}

	totalGB := float64(memInfo.ullTotalPhys) / (1024 * 1024 * 1024)
	usedGB := float64(memInfo.ullTotalPhys-memInfo.ullAvailPhys) / (1024 * 1024 * 1024)

	return fmt.Sprintf("%.1f GiB / %.1f GiB", usedGB, totalGB)
}

// getDiskInfo retrieves disk space information for the system drive.
//
// Returns:
//   - A formatted string showing used/total disk space (e.g., "250.5 GB / 500.0 GB")
//   - "Unknown" if the GetDiskFreeSpaceEx call fails
//
// Queries the C: drive by default using Windows GetDiskFreeSpaceEx API.
func getDiskInfo() string {
	var freeBytesAvailable, totalBytes, totalFreeBytes uint64

	drive, derr := windows.UTF16PtrFromString("C:\\")
	if derr != nil {
		return "Unknown"
	}
	err := windows.GetDiskFreeSpaceEx(
		drive,
		&freeBytesAvailable,
		&totalBytes,
		&totalFreeBytes,
	)

	if err != nil {
		return "Unknown"
	}

	const gib = 1024 * 1024 * 1024
	totalGiB := float64(totalBytes) / float64(gib)
	usedGiB := float64(totalBytes-totalFreeBytes) / float64(gib)

	return fmt.Sprintf("%.1f GiB / %.1f GiB", usedGiB, totalGiB)
}

// getRegistryString is a helper function to safely read string values from the Windows registry.
//
// Parameters:
//   - key: The root registry key (e.g., registry.LOCAL_MACHINE)
//   - path: The registry path to open
//   - valueName: The name of the value to read
//
// Returns:
//   - The string value if successful
//   - An empty string if the key, path, or value doesn't exist or can't be read
//
// This function handles all errors internally and provides a clean interface for registry access.
func getRegistryString(key registry.Key, path string, valueName string) string {
	k, err := registry.OpenKey(key, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer func() { _ = k.Close() }()

	value, _, err := k.GetStringValue(valueName)
	if err != nil {
		return ""
	}

	return value
}

// rtlGetVersion calls ntdll.RtlGetVersion to obtain accurate Windows version info.
func rtlGetVersion() (major uint32, minor uint32, build uint32, err error) {
	// OSVERSIONINFOEXW
	type osver struct {
		dwOSVersionInfoSize uint32
		dwMajorVersion      uint32
		dwMinorVersion      uint32
		dwBuildNumber       uint32
		dwPlatformID        uint32
		szCSDVersion        [128]uint16
		wServicePackMajor   uint16
		wServicePackMinor   uint16
		wSuiteMask          uint16
		wProductType        byte
		wReserved           byte
	}

	var v osver
	v.dwOSVersionInfoSize = uint32(unsafe.Sizeof(v))

	ret, _, callErr := procRtlGetVersion.Call(uintptr(unsafe.Pointer(&v)))
	if ret != 0 {
		// non-zero result indicates failure
		if callErr != nil && callErr != syscall.Errno(0) {
			return 0, 0, 0, callErr
		}
		return 0, 0, 0, fmt.Errorf("RtlGetVersion failed: ret=%d", ret)
	}

	return v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber, nil
}

// getLocalIP returns the best local IPv4 address (prefers private addresses).
func getLocalIP() string {
	// Try authoritative Windows API (GetBestInterface) first
	if ip := getLocalIPBestIface(); ip != "" {
		return ip
	}

	// Prefer the outbound/default-route address: create a UDP "connection" to
	// a public IP and read the local address used. This avoids picking virtual
	// adapters (VMware, virtual switches) when they're not used for outbound.
	d := net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := d.Dial("udp", "8.8.8.8:53")
	var nonPrivateCandidate string
	if err == nil {
		if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			ip4 := ua.IP.To4()
			if ip4 != nil && !ip4.IsLoopback() {
				// Prefer RFC1918 private addresses (10/8, 172.16/12, 192.168/16)
				if isPrivateIP(ip4) {
					_ = conn.Close()
					return ip4.String()
				}
				// otherwise keep as a non-private candidate to fall back to later
				nonPrivateCandidate = ip4.String()
			}
		}
		_ = conn.Close()
	}

	// Fallback: scan interfaces but prefer physical-looking interface names and
	// avoid virtual adapters by name.
	badNames := []string{"vmware", "vbox", "virtual", "veth", "docker", "hyper-v", "loopback", "hamachi", "tunnel"}
	// Prefer Ethernet (wired) interfaces first when scanning fallbacks, then Wi‑Fi.
	preferNames := []string{"eth", "ethernet", "lan", "en", "wi", "wlan", "wifi", "wireless"}

	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	var candidates []struct {
		name string
		ip   string
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		lname := strings.ToLower(iface.Name)
		skip := false
		for _, bad := range badNames {
			if strings.Contains(lname, bad) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			candidates = append(candidates, struct{ name, ip string }{iface.Name, ip4.String()})
		}
	}

	// Prefer candidates whose interface name looks like Wi-Fi or Ethernet.
	for _, pref := range preferNames {
		for _, c := range candidates {
			if strings.Contains(strings.ToLower(c.name), pref) {
				return c.ip
			}
		}
	}

	// Otherwise return first candidate if any
	if len(candidates) > 0 {
		return candidates[0].ip
	}

	// If we had a non-private UDP-derived candidate, return it as a last resort
	if nonPrivateCandidate != "" {
		return nonPrivateCandidate
	}

	return ""
}

// isPrivateIP checks for RFC1918 addresses (10/8, 172.16/12, 192.168/16)
func isPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		b0 := ip4[0]
		b1 := ip4[1]
		switch {
		case b0 == 10:
			return true
		case b0 == 172 && b1 >= 16 && b1 <= 31:
			return true
		case b0 == 192 && b1 == 168:
			return true
		}
	}
	return false
}

// getWANIP queries a small list of public IP services with short timeouts and
// returns the first successful IPv4 address. Returns empty string on failure.
func getWANIP() string {
	services := []string{
		"https://api.ipify.org",
		"https://icanhazip.com",
	}

	client := &http.Client{Timeout: 1500 * time.Millisecond}
	for _, url := range services {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			continue
		}
		ipStr := strings.TrimSpace(string(body))
		if net.ParseIP(ipStr) != nil {
			return ipStr
		}
	}

	return ""
}

// getLocalIPBestIface uses the Windows GetBestInterface API to find the
// interface index for a given destination (8.8.8.8) and returns the IPv4
// address assigned to that interface. Returns empty string on failure.
func getLocalIPBestIface() string {
	// Destination IP to use for route selection
	destIP := net.ParseIP("8.8.8.8").To4()
	if destIP == nil {
		return ""
	}

	// GetBestInterface expects the destination IPv4 address as a DWORD in
	// network byte order (big-endian). Convert using binary.BigEndian.
	dest := binary.BigEndian.Uint32(destIP)

	var ifIndex uint32
	ret, _, _ := procGetBestInterface.Call(uintptr(dest), uintptr(unsafe.Pointer(&ifIndex)))
	if ret != 0 {
		return ""
	}

	// Map interface index to net.Interface and return its first IPv4 address.
	ifi, err := net.InterfaceByIndex(int(ifIndex))
	if err != nil {
		return ""
	}

	addrs, err := ifi.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			ip4 := v.IP.To4()
			if ip4 != nil && !ip4.IsLoopback() {
				return ip4.String()
			}
		case *net.IPAddr:
			ip4 := v.IP.To4()
			if ip4 != nil && !ip4.IsLoopback() {
				return ip4.String()
			}
		}
	}

	return ""
}

// hasInternetConnectivity performs a lightweight TCP dial to a well-known
// public DNS server to determine whether the host has basic internet access.
// It returns true if a short TCP connection can be established.
func hasInternetConnectivity(timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", "8.8.8.8:53", timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
