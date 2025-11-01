
```markdown
# xfetch

xfetch is a small, fast, Windows-first system information fetcher written in Go. It prints a compact summary of the host (OS, build, uptime, CPU/GPU, memory/disk), the local and public IP addresses, and an ASCII-art logo to the terminal.

![xfetch screenshot](xfetch.png)

The project favors native Windows APIs where possible and uses a single combined PowerShell/CIM query to reduce process startup overhead when gathered information requires it.

Key features

- Minimal single-binary Go program (Go 1.21+)
- Windows-native helpers for accuracy and speed (RtlGetVersion, GetTickCount64, Toolhelp snapshots, iphlpapi GetBestInterface)
- Combined PowerShell/CIM query for model/CPU/GPU/BaseBoard + robust fallbacks
- Local outbound IP detection (GetBestInterface + UDP-dial fallback + interface heuristics)
- WAN (public) IP lookup with short timeouts and offline gating
- Uptime computed from multiple sources (CIM boot time, tick count, resume events) with source annotation
- ANSI-colored output; uses runewidth to compute visible widths for alignment

Build

This repository targets Go 1.21 or later. On Windows (from the repository root):

```powershell
# build the executable
go build -o xfetch.exe .
```

Run

Just run the built binary. On Windows you can invoke it from PowerShell or cmd:

```powershell
.\xfetch.exe
```

Output fields

The program prints a short list of fields. Typical labels you will see include:

- OS — product name and (when available) display version
- Host — computer model or BaseBoard (motherboard) product/manufacturer
- Local IP — the selected local IPv4 address used for outbound traffic (authoritative selection)
- WAN IP — public IPv4 address (queried from public services; skipped when offline)
- Build — Windows build number (e.g. "Build 26200")
- Uptime — human-friendly uptime plus the source used (powerShell, tick, resume)
- CPU, GPU, Memory, Disk, Shell, Resolution, Terminal, Packages

Environment / runtime hints

- XFETCH_DEBUG=1 — enable debug prints to stderr for troubleshooting PowerShell parsing, tick/uptime comparisons, and other diagnostics.
- ANSI colors: modern terminals (Windows Terminal, recent conhost) support VT sequences. If your terminal does not, colors may appear as escape sequences.

Code layout

- `main.go` — CLI and rendering (layout, color bar, ASCII art)
- `sysinfo/` — system information gatherers and Windows-specific implementations
	- `sysinfo/sysinfo.go` — shared types and dispatcher
	- `sysinfo/windows.go` — Windows-only implementation (build tag `//go:build windows`)
- `ascii/` — ASCII logos used by the renderer

Dependencies

- golang.org/x/sys — Windows system calls and registry helpers
- github.com/mattn/go-runewidth — visible width calculation for Unicode/wide runes

Testing and CI

There are unit tests for small helper functions under `sysinfo/`. Before publishing, consider adding a GitHub Actions workflow to run `go test` on multiple Go versions and platforms.

Privacy and network behavior

- xfetch may call external services briefly to determine your public IP. This happens only when the program detects internet connectivity and queries a short list of public IP endpoints with short timeouts.
- The program does not phone home with machine-identifying telemetry beyond the optional public-IP lookup; be mindful when running on untrusted networks.

Contributing

Contributions are welcome. A good first step is to open issues for small improvements (macOS/Linux support, additional tests, CLI flags). If you plan to submit PRs:

1. Fork the repository and create a feature branch.
2. Run `go fmt ./...` and `go test ./...` before opening a PR.
3. Keep Windows-specific code inside `//go:build windows` files.

License

Add an appropriate license file (e.g., `LICENSE`) before publishing. If you want, I can add an MIT or Apache-2.0 license file for you.
"# xfetch

xfetch is a small, fast, Windows-first system information fetcher written in Go. It prints a compact summary of the host (OS, build, uptime, CPU/GPU, memory/disk), the local and public IP addresses, and an ASCII-art logo to the terminal.

The project favors native Windows APIs where possible and uses a single combined PowerShell/CIM query to reduce process startup overhead when gathered information requires it.

## Key features

- Minimal single-binary Go program (Go 1.21+)
- Windows-native helpers for accuracy and speed (RtlGetVersion, GetTickCount64, Toolhelp snapshots, iphlpapi GetBestInterface)
- Combined PowerShell/CIM query for model/CPU/GPU/BaseBoard + robust fallbacks
- Authoritative local outbound IP detection (GetBestInterface) with UDP-dial and interface heuristics as fallbacks
- WAN (public) IP lookup with short timeouts and offline gating
- Uptime computed from multiple sources (CIM boot time, tick count, resume events) with source annotation
- ANSI-colored output; uses runewidth to compute visible widths for alignment
- Top-aligned ASCII art and a 16-color background bar for a compact, readable layout

## Build

This repository targets Go 1.21 or later. On Windows (from the repository root):

```powershell
# build the executable
go build -o xfetch.exe .
```

## Run

Run the built binary from PowerShell or cmd:

```powershell
.\xfetch.exe
```

## Output fields

Typical output labels include:

- OS — product name and (when available) display version
- Host — computer model or BaseBoard (motherboard) product/manufacturer
- Local IP — the selected local IPv4 address used for outbound traffic
- WAN IP — public IPv4 address (queried from public services; skipped when offline)
- Build — Windows build number (e.g. "Build 26200")
- Uptime — human-friendly uptime plus the source used (powerShell, tick, resume)
- CPU, GPU, Memory, Disk, Shell, Resolution, Terminal, Packages

## Environment / runtime hints

- XFETCH_DEBUG=1 — enable debug prints to stderr for troubleshooting PowerShell parsing, tick/uptime comparisons, and other diagnostics.
- ANSI colors: modern terminals (Windows Terminal, recent conhost) support VT sequences. If your terminal does not, colors may appear as escape sequences.

## Code layout

- `main.go` — CLI and rendering (layout, color bar, ASCII art)
- `sysinfo/` — system information gatherers and Windows-specific implementations
  - `sysinfo/sysinfo.go` — shared types and dispatcher
  - `sysinfo/windows.go` — Windows-only implementation (build tag `//go:build windows`)
- `ascii/` — ASCII logos used by the renderer

## Dependencies

- golang.org/x/sys — Windows system calls and registry helpers
- github.com/mattn/go-runewidth — visible width calculation for Unicode/wide runes

## Testing and CI

There are unit tests for small helper functions under `sysinfo/`. Consider adding a GitHub Actions workflow to run `go test` on multiple Go versions and platforms before publishing.

## Privacy and network behavior

- xfetch may call external services briefly to determine your public IP. This happens only when the program detects internet connectivity and queries a short list of public IP endpoints with short timeouts.
- The program does not phone home with machine-identifying telemetry beyond the optional public-IP lookup; be mindful when running on untrusted networks.

## License

This repository is licensed under the MIT License. See `LICENSE` for details (Copyright 2025 Morten Johansen <mojoaar@atomicmail.io>).

## Contributing

Contributions are welcome. A good first step is to open issues for small improvements (macOS/Linux support, additional tests, CLI flags). If you plan to submit PRs:

1. Fork the repository and create a feature branch.
2. Run `go fmt ./...` and `go test ./...` before opening a PR.
3. Keep Windows-specific code inside `//go:build windows` files.

## History

### v1.0.0 (November 1, 2025)

**Initial stable release**

- Windows-native system information fetcher with ANSI-colored output
- Authoritative local IP detection using GetBestInterface API with UDP-dial and interface-name heuristics as fallbacks
- WAN (public) IP lookup with short timeouts and offline gating
- Combined PowerShell/CIM query for model, CPU, GPU, and BaseBoard (motherboard) information
- Multi-source uptime calculation (CIM boot time, GetTickCount64, resume events) with source annotation
- Native Windows APIs: RtlGetVersion for OS version detection, Toolhelp snapshots for parent process lookup, iphlpapi for network interface selection
- Centralized PowerShell execution helper with timeouts to prevent hangs
- Top-aligned ASCII art with configurable gap spacing and 16-color background bar
- CLI flags: `--compact`, `--gap`, `--no-wan`, `--debug`
- Comprehensive linter fixes (errcheck, staticcheck, revive, ineffassign)
- MIT License and security/contributing documentation
- GitHub Actions CI workflow for cross-platform testing
