#!/usr/bin/env python3
"""
Shark OAuth Redirect Capture Helper (Cross-Platform)

Captures the OAuth redirect URL from Shark's Auth0 login flow by temporarily
registering a protocol handler for the com.sharkninja.shark:// custom scheme.

Supports macOS, Windows, and Linux. Uses only Python standard library modules.

Usage:
    python3 shark_oauth_helper.py "https://auth0-login-url..."
    python3 shark_oauth_helper.py          # will prompt for the URL
"""

import argparse
import os
import platform
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import webbrowser
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROTOCOL = "com.sharkninja.shark"
TIMEOUT_SECONDS = 600  # 10 minutes
POLL_INTERVAL = 0.2    # seconds


# ---------------------------------------------------------------------------
# Clipboard helper
# ---------------------------------------------------------------------------

def copy_to_clipboard(text: str) -> bool:
    """Copy *text* to the system clipboard.  Returns True on success."""
    system = platform.system()
    try:
        if system == "Darwin":
            subprocess.run(["pbcopy"], input=text.encode(), check=True)
        elif system == "Linux":
            try:
                subprocess.run(
                    ["xclip", "-selection", "clipboard"],
                    input=text.encode(), check=True,
                )
            except FileNotFoundError:
                subprocess.run(
                    ["xsel", "--clipboard", "--input"],
                    input=text.encode(), check=True,
                )
        elif system == "Windows":
            subprocess.run(["clip"], input=text.encode(), check=True)
        else:
            return False
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Manual-capture instructions (fallback for all platforms)
# ---------------------------------------------------------------------------

MANUAL_INSTRUCTIONS = textwrap.dedent("""\

    === Manual Capture Instructions ===

    If the automatic capture did not work you can grab the redirect URL
    yourself using your browser's developer tools:

    1. Open your browser and press F12 (or Cmd+Option+I on macOS) to open
       DevTools.
    2. Go to the *Network* tab.
    3. Paste the Auth0 login URL into the address bar and complete the login.
    4. After login the browser will try to navigate to a URL starting with
       com.sharkninja.shark://  -- it will fail with a "can't open" error.
    5. In the Network tab, find the request whose URL starts with
       com.sharkninja.shark://
    6. Right-click the request -> "Copy" -> "Copy URL".
    7. Paste this URL into Home Assistant when prompted.
""")


# ---------------------------------------------------------------------------
# Platform: macOS
# ---------------------------------------------------------------------------

def _macos_applescript_source(capture_file: str) -> str:
    """Return the AppleScript source for the temporary .app handler.

    macOS delivers custom-scheme URLs via Apple Events (kAEGetURL), not as
    command-line arguments.  An AppleScript applet compiled with osacompile
    handles the ``open location`` event natively.

    The applet writes the received URL to *capture_file* and quits.
    """
    return textwrap.dedent(f"""\
        on open location this_URL
            try
                set captureFile to POSIX file "{capture_file}"
                set fRef to open for access captureFile with write permission
                write this_URL to fRef as <<class utf8>>
                close access fRef
            end try
            quit
        end open location
    """)


def setup_macos(capture_file: str) -> str:
    """Register a temporary .app bundle as the URL-scheme handler on macOS.

    Uses ``osacompile`` to build a genuine AppleScript applet (which
    correctly receives Apple Events), then patches the generated
    ``Info.plist`` to declare the ``com.sharkninja.shark`` URL scheme.

    Returns the path to the temporary .app for later cleanup.
    """
    import plistlib  # macOS-only; deferred so the script loads on all platforms

    tmp_dir = tempfile.mkdtemp(prefix="SharkOAuth_")

    # Write the raw AppleScript source to a temp file.
    script_file = os.path.join(tmp_dir, "handler.applescript")
    with open(script_file, "w") as f:
        f.write(_macos_applescript_source(capture_file))

    # Compile into a full .app bundle via osacompile.
    app_path = os.path.join(tmp_dir, "SharkOAuth.app")
    subprocess.run(
        ["osacompile", "-o", app_path, script_file],
        check=True, capture_output=True,
    )

    # Patch the generated Info.plist to register our URL scheme.
    plist_path = os.path.join(app_path, "Contents", "Info.plist")
    with open(plist_path, "rb") as f:
        plist = plistlib.load(f)
    plist["CFBundleURLTypes"] = [
        {
            "CFBundleURLName": "Shark OAuth Redirect",
            "CFBundleURLSchemes": [PROTOCOL],
        }
    ]
    with open(plist_path, "wb") as f:
        plistlib.dump(plist, f, fmt=plistlib.FMT_XML)

    # Register the app with Launch Services so macOS knows about the scheme.
    lsregister = (
        "/System/Library/Frameworks/CoreServices.framework"
        "/Frameworks/LaunchServices.framework/Support/lsregister"
    )
    subprocess.run(
        [lsregister, "-R", "-f", app_path],
        check=True, capture_output=True,
    )

    return app_path


def cleanup_macos(app_path: str) -> None:
    """Unregister and delete the temporary .app bundle."""
    lsregister = (
        "/System/Library/Frameworks/CoreServices.framework"
        "/Frameworks/LaunchServices.framework/Support/lsregister"
    )
    try:
        subprocess.run(
            [lsregister, "-u", app_path],
            check=False, capture_output=True,
        )
    except Exception:
        pass

    # Delete the entire temp directory that contains the .app.
    tmp_dir = os.path.dirname(app_path)
    try:
        shutil.rmtree(tmp_dir)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Platform: Windows
# ---------------------------------------------------------------------------

def setup_windows(capture_file: str) -> str:
    """Register an HKCU protocol handler on Windows.

    Creates a small Python handler script and points the registry at it.
    Returns the temp directory used, for later cleanup.
    """
    import winreg  # available only on Windows

    tmp_dir = tempfile.mkdtemp(prefix="SharkOAuth_")
    handler_script = os.path.join(tmp_dir, "handler.py")

    # The handler script is invoked by Windows when the browser navigates to
    # com.sharkninja.shark://...  Windows passes the full URL as %1.
    with open(handler_script, "w") as f:
        f.write(textwrap.dedent(f"""\
            import sys
            url = sys.argv[1] if len(sys.argv) > 1 else ""
            url = url.strip().strip('"')
            with open(r"{capture_file}", "w") as fh:
                fh.write(url)
        """))

    # Build the shell command the registry will execute.
    python_exe = sys.executable
    cmd = f'"{python_exe}" "{handler_script}" "%1"'

    root_key = f"Software\\Classes\\{PROTOCOL}"
    try:
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, root_key)
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, f"URL:{PROTOCOL} Protocol")
        winreg.SetValueEx(key, "URL Protocol", 0, winreg.REG_SZ, "")
        winreg.CloseKey(key)

        cmd_key = winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER, f"{root_key}\\shell\\open\\command"
        )
        winreg.SetValueEx(cmd_key, "", 0, winreg.REG_SZ, cmd)
        winreg.CloseKey(cmd_key)
    except Exception as exc:
        raise RuntimeError(f"Failed to create registry entries: {exc}") from exc

    return tmp_dir


def cleanup_windows(tmp_dir: str) -> None:
    """Remove registry entries and temp files on Windows."""
    import winreg

    root_key = f"Software\\Classes\\{PROTOCOL}"

    def _delete_tree(hive, path):
        """Recursively delete a registry key tree."""
        try:
            key = winreg.OpenKeyEx(hive, path, 0, winreg.KEY_ALL_ACCESS)
        except FileNotFoundError:
            return
        while True:
            try:
                subkey = winreg.EnumKey(key, 0)
                _delete_tree(hive, f"{path}\\{subkey}")
            except OSError:
                break
        winreg.CloseKey(key)
        try:
            winreg.DeleteKey(hive, path)
        except Exception:
            pass

    _delete_tree(winreg.HKEY_CURRENT_USER, root_key)

    try:
        shutil.rmtree(tmp_dir)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Platform: Linux
# ---------------------------------------------------------------------------

def setup_linux(capture_file: str) -> str:
    """Register a .desktop file as the URL-scheme handler on Linux.

    Creates a handler script and a .desktop entry, then uses ``xdg-mime``
    to set it as the default for the custom scheme.

    Returns the temp directory used, for later cleanup.
    """
    tmp_dir = tempfile.mkdtemp(prefix="SharkOAuth_")
    handler_script = os.path.join(tmp_dir, "handler.py")

    with open(handler_script, "w") as f:
        f.write(textwrap.dedent(f"""\
            #!/usr/bin/env python3
            import sys
            url = sys.argv[1] if len(sys.argv) > 1 else ""
            url = url.strip().strip('"')
            with open(r"{capture_file}", "w") as fh:
                fh.write(url)
        """))
    os.chmod(handler_script, os.stat(handler_script).st_mode | stat.S_IEXEC)

    desktop_dir = os.path.expanduser("~/.local/share/applications")
    os.makedirs(desktop_dir, exist_ok=True)
    desktop_file = os.path.join(desktop_dir, "shark-oauth-helper.desktop")

    with open(desktop_file, "w") as f:
        f.write(textwrap.dedent(f"""\
            [Desktop Entry]
            Type=Application
            Name=Shark OAuth Helper
            Exec=python3 {handler_script} %u
            MimeType=x-scheme-handler/{PROTOCOL};
            NoDisplay=true
        """))

    # Tell the desktop environment to use our .desktop file for this scheme.
    subprocess.run(
        [
            "xdg-mime", "default",
            "shark-oauth-helper.desktop",
            f"x-scheme-handler/{PROTOCOL}",
        ],
        check=True, capture_output=True,
    )

    return tmp_dir  # desktop_file path is deterministic from this


def cleanup_linux(tmp_dir: str) -> None:
    """Remove the .desktop file and temp files on Linux."""
    desktop_file = os.path.expanduser(
        "~/.local/share/applications/shark-oauth-helper.desktop"
    )
    try:
        os.remove(desktop_file)
    except Exception:
        pass

    # Best-effort reset of xdg-mime.  If there was a previous handler we
    # cannot easily restore it, so we simply remove ours.
    try:
        subprocess.run(
            [
                "xdg-mime", "default", "",
                f"x-scheme-handler/{PROTOCOL}",
            ],
            check=False, capture_output=True,
        )
    except Exception:
        pass

    try:
        shutil.rmtree(tmp_dir)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

def wait_for_capture(capture_file: str) -> Optional[str]:
    """Poll *capture_file* until it exists or we time out.

    Returns the captured URL string, or None on timeout.
    """
    deadline = time.monotonic() + TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if os.path.isfile(capture_file):
            try:
                with open(capture_file, "r") as f:
                    url = f.read().strip().strip('"')
                if url:
                    return url
            except Exception:
                pass
        time.sleep(POLL_INTERVAL)
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Shark OAuth redirect URL capture helper.",
    )
    parser.add_argument(
        "url",
        nargs="?",
        default=None,
        help="The Auth0 login URL.  If omitted you will be prompted.",
    )
    args = parser.parse_args()

    login_url = args.url
    if not login_url:
        print("Paste the Auth0 login URL and press Enter:")
        login_url = input("> ").strip()

    if not login_url:
        print("ERROR: No URL provided.", file=sys.stderr)
        sys.exit(1)

    system = platform.system()
    print()
    print(f"Platform detected: {system}")
    print(f"Protocol scheme:   {PROTOCOL}://")
    print()

    # Create a temp file path that the handler will write the captured URL to.
    tmp_fd, capture_file = tempfile.mkstemp(
        prefix="shark_oauth_capture_", suffix=".txt",
    )
    os.close(tmp_fd)
    os.remove(capture_file)  # handler creates it; we just reserve the path

    platform_tmp = None  # platform-specific artefact to clean up later

    # ---- Register handler ------------------------------------------------
    try:
        print("Registering temporary protocol handler ...")
        if system == "Darwin":
            platform_tmp = setup_macos(capture_file)
        elif system == "Windows":
            platform_tmp = setup_windows(capture_file)
        elif system == "Linux":
            platform_tmp = setup_linux(capture_file)
        else:
            print(f"WARNING: Unsupported platform '{system}'.")
            print("Automatic capture is not available.")
            print(MANUAL_INSTRUCTIONS)
            sys.exit(1)
        print("Handler registered.")
    except Exception as exc:
        print(f"WARNING: Could not register handler: {exc}")
        print("Falling back to manual instructions.")
        print(MANUAL_INSTRUCTIONS)
        sys.exit(1)

    def _cleanup():
        """Remove handler and temp files."""
        print()
        print("Cleaning up temporary handler ...")
        try:
            if system == "Darwin" and platform_tmp:
                cleanup_macos(platform_tmp)
            elif system == "Windows" and platform_tmp:
                cleanup_windows(platform_tmp)
            elif system == "Linux" and platform_tmp:
                cleanup_linux(platform_tmp)
        except Exception:
            pass
        try:
            os.remove(capture_file)
        except Exception:
            pass
        print("Cleanup complete.")

    # Ensure cleanup runs on Ctrl+C.
    def _signal_handler(sig, frame):
        _cleanup()
        sys.exit(130)

    signal.signal(signal.SIGINT, _signal_handler)

    # ---- Open browser ----------------------------------------------------
    print()
    print("Opening login URL in your default browser ...")
    webbrowser.open(login_url)

    print()
    print("READY -- complete the login in your browser.")
    print("This script will automatically detect the redirect.")
    print(f"(timeout: {TIMEOUT_SECONDS // 60} minutes)")
    print()

    # ---- Wait for redirect -----------------------------------------------
    captured_url = wait_for_capture(capture_file)

    if captured_url:
        print("-" * 60)
        print("CAPTURED -- redirect URL received")
        print("-" * 60)
        print()
        print(captured_url)
        print()

        if copy_to_clipboard(captured_url):
            print("(copied to clipboard)")
        else:
            print("(could not copy to clipboard -- please copy manually)")

        print()
        print("Paste this URL into Home Assistant when prompted.")
    else:
        print()
        print("TIMED OUT waiting for the redirect.")
        print(
            "If you completed login but nothing was captured, another app "
            "may be handling the redirect scheme."
        )
        print(MANUAL_INSTRUCTIONS)

    # ---- Cleanup ---------------------------------------------------------
    _cleanup()


if __name__ == "__main__":
    main()
