# Troubleshooting

Problems encountered while building the lab, and how they were resolved.

| Problem | Cause | Fix |
|---|---|---|
| `Get-WindowsOptionalFeature: The requested operation requires elevation.` | The PowerShell window was not running as administrator. A `C:\Windows\System32` prompt does not prove elevation. | Open a new window with **Run as administrator** (or `Start-Process pwsh -Verb RunAs`). Confirm with the `IsInRole(...Administrator)` check, which should print `True`. |
| PowerShell output froze and the title bar started with "Select" | Clicking inside a classic console window enters selection mode, which pauses the running program. | Press **Esc** (cancel) or **Enter** (copy) to leave selection mode. Windows Terminal does not pause programs on selection. |
| `Get-WindowsOptionalFeature` hung with no output | The DISM servicing query can stall, for example while Windows Update is busy. | Cancel with **Ctrl+C**. Use `Get-Service vmms` instead: the service exists only when Hyper-V is enabled. |
| `wsl -l -v` offered to install WSL | WSL was not installed, so the command prompted for installation. | Press **Esc** to cancel. WSL is not needed for this lab. |
