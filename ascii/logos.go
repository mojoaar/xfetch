// Package ascii provides ASCII art logos for different Windows editions.
// Logos are color-coded using ANSI escape sequences for terminal display.
package ascii

import "xfetch/sysinfo"

// GetLogo returns the appropriate ASCII art logo based on the Windows edition.
//
// Parameters:
//   - isServer: Boolean indicating whether the OS is Windows Server
//
// Returns:
//   - A slice of strings, where each string represents one line of ASCII art
//   - Windows Server logo if isServer is true
//   - Windows Client logo if isServer is false
//
// The logos use ANSI color codes for visual appeal in terminal output.
func GetLogo(isServer bool) []string {
	if isServer {
		return getWindowsServerLogo()
	}
	return getWindowsClientLogo()
}

// getWindowsClientLogo returns the ASCII art for Windows Client editions.
//
// Returns:
//   - A 16-line ASCII art representation of the Windows logo
//   - Uses cyan color (ColorCyan) for the Windows flag design
//
// The logo represents the modern Windows 10/11 four-pane window design.
func getWindowsClientLogo() []string {
	c := sysinfo.ColorCyan
	r := sysinfo.ColorReset

	return []string{
		c + "                               ..,," + r,
		c + "                    ....,,:;+ccllll" + r,
		c + "      ...,,+:;  cllllllllllllllllll" + r,
		c + ",cclllllllllll  lllllllllllllllllll" + r,
		c + "llllllllllllll  lllllllllllllllllll" + r,
		c + "llllllllllllll  lllllllllllllllllll" + r,
		c + "llllllllllllll  lllllllllllllllllll" + r,
		c + "llllllllllllll  lllllllllllllllllll" + r,
		c + "llllllllllllll  lllllllllllllllllll" + r,
		c + "" + r,
		c + "llllllllllllll  lllllllllllllllllll" + r,
		c + "llllllllllllll  lllllllllllllllllll" + r,
		c + "llllllllllllll  lllllllllllllllllll" + r,
		c + "llllllllllllll  lllllllllllllllllll" + r,
		c + "llllllllllllll  lllllllllllllllllll" + r,
		c + "llllllllllllll  lllllllllllllllllll" + r,
		c + "llllllllllllll  lllllllllllllllllll" + r,
		c + "`'ccllllllllll  lllllllllllllllllll" + r,
	}
}

// getWindowsServerLogo returns the ASCII art for Windows Server editions.
//
// Returns:
//   - A 16-line ASCII art representation of the Windows Server logo
//   - Uses blue color (ColorBlue) to distinguish from client editions
//
// The Server logo uses a similar four-pane design but with blue coloring
// to visually differentiate server installations from client systems.
func getWindowsServerLogo() []string {
	c := sysinfo.ColorBlue
	r := sysinfo.ColorReset

	return []string{
		c + "        ,.=:!!t3Z3z.," + r,
		c + "       :tt:::tt333EE3" + r,
		c + "       Et:::ztt33EEEL" + r + " @Ee.,      ..,",
		c + "      ;tt:::tt333EE7" + r + " ;EEEEEEttttt33#",
		c + "     :Et:::zt333EEQ." + r + " $EEEEEttttt33QL",
		c + "     it::::tt333EEF" + r + " @EEEEEEttttt33F",
		c + "    ;3=*^```\"*4EEV" + r + " :EEEEEEttttt33@.",
		c + "    ,.=::::!t=., " + r + "`" + c + " @EEEEEEtttz33QF",
		c + "   ;::::::::zt33)" + r + "   \"4EEEtttji3P*",
		c + "  :t::::::::tt33." + r + ":Z3z..  `` ,..g.",
		c + "  i::::::::zt33F" + r + " AEEEtttt::::ztF",
		c + " ;:::::::::t33V" + r + " ;EEEttttt::::t3",
		c + " E::::::::zt33L" + r + " @EEEtttt::::z3F",
		c + "{3=*^```\"*4E3)" + r + " ;EEEtttt:::::tZ`",
		c + "             `" + r + " :EEEEtttt::::z7",
		c + "                 \"VEzjt:;;z>*`" + r,
	}
}

// GetAlternativeWindowsLogo returns a simpler, alternative Windows logo.
//
// Returns:
//   - A 10-line minimalist ASCII art representation
//   - Uses red and green colors for the four panes
//
// This alternative design is more compact and may be useful for
// constrained terminal environments or user preference.
func GetAlternativeWindowsLogo() []string {
	r := sysinfo.ColorRed
	g := sysinfo.ColorGreen
	reset := sysinfo.ColorReset

	return []string{
		r + "################  ################" + reset,
		r + "################  ################" + reset,
		r + "################  ################" + reset,
		r + "################  ################" + reset,
		r + "################  ################" + reset,
		"",
		g + "################  ################" + reset,
		g + "################  ################" + reset,
		g + "################  ################" + reset,
		g + "################  ################" + reset,
	}
}
