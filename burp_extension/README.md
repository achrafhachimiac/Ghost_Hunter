# Ghost-Hunter Burp Suite Extension

Burp extension that sends in-scope HTTP traffic to Ghost-Hunter for endpoint inventory, triage, and testing.

## 5-minute setup

### Prerequisites
1. Burp Suite Community/Pro
2. Jython standalone JAR (`jython-standalone-2.7.x.jar`)

### Install in Burp
1. `Extender → Options → Python Environment` → select Jython JAR
2. `Extender → Extensions → Add`
3. Type: `Python`
4. File: `burp_extension/ghost_hunter.py`

### Connect to Ghost-Hunter
1. Start Ghost-Hunter:
   ```bash
   ./hunt.sh start
   ```
2. Open Burp tab `Ghost-Hunter`
3. API URL should be:
   ```
   http://127.0.0.1:1010
   ```
4. Click `Save & Test Connection`

### First capture
1. Define scope in Burp: `Target → Scope`
2. Browse your target normally
3. Open dashboard:
   ```
   http://127.0.0.1:1010/dashboard
   ```
4. Confirm endpoints appear in Ghost-Hunter

## Features

- Auto-capture of in-scope requests
- Batch forwarding to Ghost-Hunter API
- Context menu actions:
  - `Send to Ghost-Hunter`
  - `Analyze with Ghost-Hunter AI`
- Built-in connection test
- Live counters in Burp tab

## Troubleshooting

### Connection failed
`Connection refused` usually means Ghost-Hunter is not running.

```bash
./hunt.sh status
./hunt.sh start
```

### No requests captured
- Ensure request is in Burp scope
- Ensure auto-capture is enabled in extension tab
- Check extension logs in Burp output

### Jython error (`No module named burp`)
Reconfigure Jython JAR in `Extender → Options`.
