# vhs tape for the vexes hero GIF.
# Render with:  vhs demo/vexes.tape   (https://github.com/charmbracelet/vhs)
# Produces demo/vexes.gif — a multi-ecosystem scan of the demo fixtures.

Output demo/vexes.gif
Output demo/vexes.mp4
Output demo/vexes.webm

Set FontSize 17
Set Width 1200
Set Height 760
Set Padding 22
# Penumbra Eclipse — palette from penumbraforge.com design tokens.
Set Theme { "name": "Penumbra Eclipse", "background": "#0a0a14", "foreground": "#e8e4ef", "cursor": "#d4c4f0", "selection": "#2e2e50", "black": "#10101c", "red": "#e0809b", "green": "#6bcf8f", "yellow": "#d9c58a", "blue": "#7d93a8", "magenta": "#b8a5d6", "cyan": "#8fc4cf", "white": "#e8e4ef", "brightBlack": "#5f5a6b", "brightRed": "#eda0b5", "brightGreen": "#8fdfab", "brightYellow": "#e8d9a8", "brightBlue": "#9db3c8", "brightMagenta": "#d4c4f0", "brightCyan": "#aed8e0", "brightWhite": "#f2eff8" }

Type "# vexes — cross-ecosystem dependency scanner. Zero dependencies."
Enter
Sleep 800ms

Type "# Scan a project with npm + PyPI + Cargo dependencies:"
Enter
Sleep 600ms
Type "vexes scan --path demo --severity high"
Enter
Sleep 5s

Type "# Machine-readable output for CI — SARIF for GitHub code scanning:"
Enter
Sleep 600ms
Type "vexes scan --path demo --format sarif | head -c 200"
Enter
Sleep 3s
Enter

Type "# And AI-assisted triage (opt-in): vexes scan --format json | vexes explain"
Enter
Sleep 2500ms
