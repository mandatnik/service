# GPO deployment

This directory contains the reference computer startup script used by the
P09 test. The agent MSI is deployed from a share; the script also writes the
GPO-managed `C:\ProgramData\Telehack2026\agent-config.json` before installing
the MSI. No CryptoPro, browser plugin, user certificate or test root is
installed by this script.

## Reference layout

```text
\\SERVER\TelehackDeploy\TelehackAgent.msi
\\SERVER\TelehackDeploy\agent-config.json
```

`agent-config.json` is a product input, not a secret:

```json
{
  "request_timeout_seconds": 30,
  "server_url": "https://backend.example:8443"
}
```

Grant read access to the deployment share for the computer accounts in the
test scope (and for administrators who need to run repair).

## GPO settings

Use a dedicated test GPO and the narrowest possible scope (a test OU or
security filtering). Never change Default Domain Policy for this test.

Create `Machine\Scripts\Startup\install-telehack.cmd` and `.ps1` from this
directory, and put `scripts.ini` at **`Machine\Scripts\scripts.ini`** — not
inside `Startup`:

```ini
[Startup]
0CmdLine=install-telehack.cmd
0Parameters=
```

New-GPO alone does not register the Scripts extension. The GPO AD object must
contain the Scripts extension names:

```text
[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]
```

and the GPT.INI/AD version must be incremented after adding the script. This
was verified from real `gpresult`/Group Policy operational logs; without these
fields the GPO can appear linked and enabled but the startup script never runs.

The tested GPO was linked to a temporary OU containing only WORKSTATION-1 and
WORKSTATION-2. The computers were returned to their original OU after the
test; the GPO, group/OU and deployment share were removed. The GPO-created
`agent-config.json` and the installed agent remain as the working stand
deployment.

## Behavior

- First boot: copy config, install MSI, start LocalSystem service.
- Later boots: copy the current GPO config and leave the existing agent/state.
- The MSI never overwrites `C:\ProgramData\Telehack2026\agent-config.json`.
- Upgrade and repair keep ProgramData state. An ordinary uninstall also keeps
  the agent identity/state; only the explicit product CLI
  `uninstall -purge` removes agent-owned state and deliberately keeps the GPO
  config.
- Repair requires the original MSI source to remain reachable (normal Windows
  Installer behavior); keep the deployment share available for repair.
