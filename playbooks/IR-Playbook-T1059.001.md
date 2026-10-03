# Incident Response Playbook: T1059.001 (Suspicious PowerShell Execution)

## 1. Alert Triage & Scope
- **Severity**: High (Level 12)
- **Log Source**: Microsoft-Windows-Sysmon/Operational (Event ID 1)
- **Initial Trigger**: `powershell.exe` execution with `-EncodedCommand` and `-ExecutionPolicy Bypass`.

## 2. Analysis & Investigation
1. **Command Decoding**:
   - Extract the Base64 payload from `win.eventdata.commandLine`.
   - Decode via CyberChef or CLI:
     ```powershell
     [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('<Base64_String>'))
     ```
2. **Parent Process Analysis**:
   - Inspect `win.eventdata.parentImage`.
   - Verify if spawned by abnormal parents (e.g., `cmd.exe`, `excel.exe`, `wscript.exe`).
3. **User & Host Context**:
   - Identify the user context (`win.eventdata.user`) and host IP address.

## 3. Containment Actions
- **Network Isolation**: Quarantine the affected host via Wazuh Active Response or EDR agent.
- **Process Termination**: Terminate active suspicious process instances matching the PID.

## 4. Eradication & Remediation
- Scan the host for dropped artifacts (e.g., check `C:\Users\Public\`, `%TEMP%`).
- Remove any unauthorized persistence keys identified in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
- Force credential rotation for any compromised user accounts.

## 5. Lessons Learned
- Refine detection threshold to alert on parent-child process anomalies.
- Implement PowerShell Constrained Language Mode (CLM) via Group Policy.