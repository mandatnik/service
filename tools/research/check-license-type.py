"""Compare Windows CPCSPLicense.GetType with SDK license_check without logging SN.

Uses an already established SSH control connection and a local CryptoPro SDK.
Does not install or change any license. Windows SDK compatibility is not implied.
"""
import base64
import ctypes
import json
from pathlib import Path
import subprocess
import sys

project = Path(__file__).resolve().parents[2]
suffix = sys.argv[1]
socket = sys.argv[2]
ps = (Path(__file__).parent / "license_type_probe.ps1").read_text()
encoded = base64.b64encode(ps.encode("utf-16le")).decode()
r = subprocess.run(["ssh", "-S", socket, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                    f"agent@192.168.189.{suffix}", "powershell.exe", "-NoProfile", "-NonInteractive",
                    "-EncodedCommand", encoded], capture_output=True, text=True, timeout=35)
if r.returncode:
    # Never include stdout/stderr: partial native output could contain a license.
    raise SystemExit(f"Remote read-only probe failed (exit={r.returncode}); raw output intentionally withheld")
raw = json.loads(r.stdout)
secret = base64.b64decode(raw.pop("LicenseBytesBase64"))
r.stdout = ""
if len(secret) >= 2 and secret[1] == 0:
    sn = secret.decode("utf-16le").rstrip("\0").encode("ascii")
else:
    sn = secret.rstrip(b"\0")
lib = ctypes.CDLL("/opt/cprocsp/lib/libcsplicense.dylib")
u32, i32, i64 = ctypes.c_uint32, ctypes.c_int32, ctypes.c_int64
lib.license_check.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(u32),
                             ctypes.POINTER(i32), ctypes.POINTER(i32), ctypes.POINTER(i32),
                             ctypes.POINTER(u32), ctypes.POINTER(i32), ctypes.POINTER(i64)]
lib.license_check.restype = u32
values = [i32(), i32(), i32(), u32(), i32(), i64()]
code = lib.license_check(sn, None, None, *[ctypes.byref(v) for v in values])
secret = sn = b""
raw.update({"sdk_check_error": f"0x{code:08x}", "sdk_platform": "local macOS libcsplicense; offline read-only check",
            "sdk_validity": values[0].value, "sdk_type": values[1].value,
            "sdk_restrictions": values[2].value, "sdk_extra": values[3].value,
            "sdk_server_flag": bool(values[3].value & 2) if code == 0 else None,
            "sdk_demo_flag": bool(values[3].value & 1) if code == 0 else None,
            "sdk_days_to_expire": values[4].value, "sdk_unix_end": values[5].value,
            "license_identifier_saved": False})
if code == 0:
    raw["license_kind_from_sdk"] = "server" if raw["sdk_server_flag"] else "client"
target = project / "research/2026-11-14" / f"license-type-sdk-{suffix}.json"
target.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n")
print(json.dumps(raw, ensure_ascii=False, indent=2))
