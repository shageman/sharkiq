# SharkIQ (Experimental / Testing)

This repository is a **custom HACS source** used for testing very new and experimental SharkIQ integration code.

---

## Install via HACS (Custom Repository)

1. In Home Assistant, open **HACS** → **Integrations**
2. Open the menu (top-right) → **Custom repositories**
3. Add this repository URL:

   - Repository: `https://github.com/TheOneOgre/sharkiq`  
   - Category: **Integration**  

4. Find **Sharkiq Dev** in HACS and install the latest release
5. **Restart Home Assistant**
6. Go to **Settings** → **Devices & services** → **Add Integration**
7. Search for and install: **Sharkiq Dev**

If you encounter any issues during install or setup, please report them on 'https://github.com/sharkiqlibs/sharkiq/issues/141'.

---

## Browser Login Helper (Optional)

Some authentication flows require completing a **browser-based OAuth login**.
Because Shark uses a mobile-style redirect URI (`com.sharkninja.shark://...`), copying the resulting redirect URL manually can be inconvenient.

For user convenience, this repository includes **helper scripts** that simplify this process.

### What the helpers do

- Temporarily register a handler for Shark’s custom redirect URI
- Wait while you click the **Login** link in Home Assistant and complete the browser login
- Automatically capture the redirect URL when the browser hands it off
- Copy the full redirect URL to your clipboard
- Display progress and the captured URL in the terminal
- **Clean up automatically** (removes the handler and all temporary files when finished)

No permanent system changes are left behind.

> **Important:**
> These helpers are **optional** and provided only as a convenience.
> The integration itself does **not** require external scripts to function.

---

## OAuth Helper Script (Cross-Platform -- Recommended)

The `shark_oauth_helper.py` script works on **macOS, Windows, and Linux** using only Python 3 (no extra dependencies).

If the integration requires interactive login (due to Auth0 "suspicious request" errors), you can use it to capture the OAuth redirect URL:

### Automatic (recommended)

```bash
python3 shark_oauth_helper.py "YOUR_AUTH0_LOGIN_URL"
```

Or run without arguments to be prompted for the URL:

```bash
python3 shark_oauth_helper.py
```

The script will:
1. Register a temporary protocol handler for the `com.sharkninja.shark://` scheme
2. Open the login URL in your default browser
3. Wait for you to complete the login
4. Capture the redirect URL and copy it to your clipboard
5. Clean up the temporary handler

Paste the captured URL into Home Assistant when prompted.

### Manual capture (fallback)

If automatic capture does not work, you can use your browser’s DevTools:

1. Open DevTools (F12 or Cmd+Option+I)
2. Go to the **Network** tab
3. Complete the login; the browser will try to navigate to `com.sharkninja.shark://...`
4. Find that request in the Network tab, right-click it, and copy the URL
5. Paste it into Home Assistant

---

## Windows PowerShell Helper (Alternative)

If you prefer a Windows-only approach, you can use the `SharkBrowserAutoAuth.ps1` script instead:

1. Open a PowerShell window
2. Run the command below
3. Return to Home Assistant and click the Shark **Login** link
4. Complete the browser login
5. Paste the captured redirect URL into Home Assistant when prompted

### One-line PowerShell command

```powershell
$u=’https://raw.githubusercontent.com/TheOneOgre/sharkiq/main/SharkBrowserAutoAuth.ps1’;$p="$env:TEMP\SharkOAuth.ps1";iwr $u -OutFile $p;& $p;rm $p
```
