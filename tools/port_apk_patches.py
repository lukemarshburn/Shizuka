#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Re-derive a profile's Bluetooth.apk smali edits from the reviewed DZIF edits.

The DZIF definitions carry inserted text and stock line indices only. For a new
firmware, each edit is re-anchored to the target's decoded smali by an explicit line
shift, and the stock text the edit was reviewed against is asserted at every anchor
before anything is written. Inserted text is reused byte for byte.

Usage: port_apk_patches.py <decoded-apk-dir> <output-json>
       (decode with: apktool d -r -o <dir> <stock Bluetooth.apk>)
"""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "profiles/samsung-sm-s931z-dzif/bluetooth-apk.json"

# SM-S948U1 / S948U1UEU5BZJA. Per file: line shift from DZIF, then for each DZIF edit
# (in order) the stock lines expected at the shifted anchor: {offset from anchor: text}.
S948U1_BZJA = {
    "smali/com/android/bluetooth/Utils$DualModeAudioSetting.smali": (
        0,
        [{-1: "", 0: "const/4 v1, 0x0", 2: ".line 196"}],
    ),
    "smali/com/android/bluetooth/btservice/AdapterService.smali": (
        -83,
        [
            # New helper method; the stock return-void/.end method close it.
            {0: "return-void", 1: ".end method", -1: ":cond_2"},
            {0: ".method public isAllSupportedClassicAudioProfilesActive(Landroid/bluetooth/BluetoothDevice;)Z"},
            {0: "invoke-virtual {p0, p1, v1}, Lcom/android/bluetooth/btservice/AdapterService;->isProfileSupported(Landroid/bluetooth/BluetoothDevice;I)Z"},
            {0: "invoke-virtual {p0, p1, v4}, Lcom/android/bluetooth/btservice/AdapterService;->isProfileSupported(Landroid/bluetooth/BluetoothDevice;I)Z"},
            # Same position as DZIF: end of the RemoteException path in
            # sendPreferredAudioProfilesCallbackToApps (p2 is the Bundle).
            {
                0: ":goto_1",
                -2: "invoke-static {v3, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I",
                1: "add-int/lit8 v1, v1, 0x1",
            },
        ],
    ),
    "smali/com/android/bluetooth/btservice/ActiveDeviceManager.smali": (
        0,
        [
            {-1: ":cond_0", 0: "invoke-static {}, Lcom/android/bluetooth/Utils;->isDualModeAudioEnabled()Z", 4: "if-eqz v0, :cond_1"},
            {-1: ":cond_1", 0: "invoke-static {}, Lcom/android/bluetooth/Utils;->isDualModeAudioEnabled()Z", 4: "if-eqz v0, :cond_2"},
        ],
    ),
    "smali/com/android/bluetooth/a2dp/A2dpCodecConfig.smali": (
        0,
        [
            {
                -1: ":cond_1",
                0: "invoke-static {p3, v0}, Lcom/android/bluetooth/a2dp/A2dpCodecConfig;->getPrioritizedCodecType(Landroid/bluetooth/BluetoothCodecConfig;Ljava/util/List;)I",
                14: "if-ne v0, v1, :cond_4",
            }
        ],
    ),
    "smali/com/android/bluetooth/a2dp/A2dpService.smali": (
        0,
        [{-3: ".method public checkHqCodecState(Landroid/bluetooth/BluetoothDevice;)Z", -2: ".locals 3", -1: ""}],
    ),
    "smali/com/android/bluetooth/le_audio/LeAudioService.smali": (
        0,
        [
            {0: ".method public setConnectionPolicy(Landroid/bluetooth/BluetoothDevice;I)Z", -1: ""},
            {
                0: "invoke-virtual {p0, p1, v2}, Lcom/android/bluetooth/le_audio/LeAudioService;->setEnabledState(Landroid/bluetooth/BluetoothDevice;Z)V",
                -3: "if-nez p2, :cond_4",
            },
        ],
    ),
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def port(decoded, mapping):
    source = json.loads(SOURCE.read_text(encoding="utf-8"))
    if [f["path"] for f in source["files"]] != list(mapping):
        raise SystemExit("File list differs from the reviewed DZIF definitions")
    files = []
    for entry in source["files"]:
        shift, anchors = mapping[entry["path"]]
        if len(anchors) != len(entry["edits"]):
            raise SystemExit(f"{entry['path']}: edit count differs")
        # apktool writes the platform line separator; digests are over LF text.
        raw = (decoded / entry["path"]).read_bytes().replace(b"\r\n", b"\n")
        lines = raw.decode("utf-8").splitlines(keepends=True)
        edits = []
        for edit, expected in zip(entry["edits"], anchors):
            line = edit["line"] + shift
            for offset, text in expected.items():
                actual = lines[line + offset].strip()
                if actual != text:
                    raise SystemExit(
                        f"{entry['path']}:{line + offset + 1}: expected {text!r}, found {actual!r}"
                    )
            edits.append({"line": line, "delete": edit["delete"], "insert": edit["insert"]})
        patched = list(lines)
        for edit in reversed(edits):
            patched[edit["line"] : edit["line"] + edit["delete"]] = edit["insert"].splitlines(
                keepends=True
            )
        files.append(
            {
                "path": entry["path"],
                "before_sha256": sha256(raw),
                "after_sha256": sha256("".join(patched).encode("utf-8")),
                "edits": edits,
            }
        )
    return {"schema": source["schema"], "files": files}


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    result = port(Path(sys.argv[1]), S948U1_BZJA)
    Path(sys.argv[2]).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(result['files'])} files, {sum(len(f['edits']) for f in result['files'])} edits re-anchored")


if __name__ == "__main__":
    main()
