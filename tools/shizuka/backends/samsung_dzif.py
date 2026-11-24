# SPDX-License-Identifier: GPL-2.0-only
"""Samsung native ABI (DZIF payload), per-firmware hook layouts and patch construction.

Not a generic device driver: every supported firmware has an explicit, reviewed
Layout keyed by its exact profile id. There is no fallback between layouts."""

import hashlib
import io
import json
import struct
import subprocess
from dataclasses import dataclass

from elftools.elf.elffile import ELFFile

from ..project import BUILD, ROOT, inputs_dir, native_options, ndk_bin

SRC = ROOT / "src"
DRIVER_SRC = SRC / "backends/samsung_dzif"

SPEC = {
    "native": (
        "libbluetooth_jni.so",
        {
            "prs_cfg": 0x9BA5E4,
            "bld_cfg": 0x9B9DEC,
            "to_hal": 0x873758,
            "enabled": 0x874E50,
            "specific": 0x959F48,
            "vendor": 0x9E9DCC,
            "new_type": 0x3FB8E4,
            "supported": 0x3F5DE4,
            "prepare": 0x3F78C4,
            "callback": 0x3F8228,
            "user": 0x95A330,
            "factory": 0x959C70,
            "supported_ss": 0x95C1FC,
            "source_index": 0x95C9CC,
            "init_codec": 0x960214,
            "vendor_source_index": 0x970F3C,
            "provider_index": 0x8000BC,
            "type_eq": 0x95ACC8,
            "equal": 0x95A520,
            "vendor_type_eq": 0x9708E4,
            "hd_type_eq": 0x97645C,
            "hd_equal": 0x97656C,
            "ll_selectable": 0x64AF14,
            "ll_sep_index": 0x653778,
            "ll_msg_send": 0x9B85FC,
        },
    ),
    "hal": ("libsehbluetooth_audio_session_aidl.so", {"validate": 0xE988}),
}


def branch(src, dst):
    delta = dst - src
    assert delta % 4 == 0 and -(1 << 27) <= delta < (1 << 27)
    return struct.pack("<I", 0x14000000 | ((delta >> 2) & 0x3FFFFFF))


def read_vaddr(elf, addr, size):
    for s in elf.iter_sections():
        if (
            s["sh_type"] != "SHT_NOBITS"
            and s["sh_addr"] <= addr
            and addr + size <= s["sh_addr"] + s["sh_size"]
        ):
            return s.data()[addr - s["sh_addr"] : addr - s["sh_addr"] + size]
    raise RuntimeError("address not in file")


def b_ne(addr, target):
    """Encode `b.ne target` at addr (imm19)."""
    return 0x54000001 | ((((target - addr) // 4) & 0x7FFFF) << 5)


NOP = 0xD503201F


@dataclass(frozen=True)
class LlVeneer:
    """Private-LL (index 9) dispatch veneer: gate is replaced by a branch to the veneer,
    which sends 9 to `match` and replays the original `cmp w8, #replay_cmp` otherwise."""

    suffix: str
    replay_cmp: int
    gate: int
    match: int
    resume: int


@dataclass(frozen=True)
class Layout:
    profile_id: str
    spec: dict
    malloc_got: int
    ll_veneers: tuple
    # (vaddr, replacement word, manifest hook name), applied to the native library.
    word_patches: tuple
    # Extra compiler definitions per flavor ("native" / "hal").
    defines: dict
    dispatch_check: str


DZIF = Layout(
    profile_id="sm-s931z-dzif-aptx-experiment",
    spec=SPEC,
    malloc_got=0xEA65E0,
    ll_veneers=(
        LlVeneer("hal", 5, 0x8561C4, 0x8561E0, 0x8561C8),
        LlVeneer("offload", 2, 0x64961C, 0x649658, 0x649620),
    ),
    word_patches=(
        (0x95E6D4, 0x71002AFF, "initialize-ll-source-slot9"),
        (0x95C238, NOP, "enable-hd-slot"),
        # The stock Samsung dispatcher only routes indices 2/3 to the aptX converter.
        # Here w8 is bounded to 4 or 5; preserve LDAC 4, route private Adaptive 5.
        (0x856458, b_ne(0x856458, 0x8561E0), "dispatch-private-adaptive-to-converter"),
        # The offload builder has the same bounded 4/5 branch; 5 needs HD framing
        # before s25_specific supplies Adaptive's real controller configuration.
        (0x649638, b_ne(0x649638, 0x649724), "dispatch-private-adaptive-offload-builder"),
    ),
    defines={},
    dispatch_check="dispatch_emulation_check.py",
)

# SM-S948U1 / S948U1UEU5BZJA (S26 Ultra). Mapped from the stock image's MiniDebugInfo
# symbols; see docs/S26-ULTRA-MAPPING.md. The vendor audio HAL is AOSP-only (no SEH
# audio provider is registered), so the seh_aidl converter hooks are replaced by one
# getHalCodecConfiguration hook, and private aptX LL (slot 9, SEH dispatch) is not
# enabled: no slot-9 initialization, no LL veneers, no LL codec advertised.
S948U1_BZJA = Layout(
    profile_id="sm-s948u1-bzja-aptx-experiment",
    spec={
        "native": (
            "libbluetooth_jni.so",
            {
                "prs_cfg": 0x9BACA0,
                "bld_cfg": 0x9BA4A8,
                "hal_codec": 0x8499C4,
                "specific": 0x95A604,
                "vendor": 0x9EA488,
                "new_type": 0x3FB8E4,
                "supported": 0x3F5DE4,
                "prepare": 0x3F78C4,
                "callback": 0x3F8228,
                "user": 0x95A9EC,
                "factory": 0x95A32C,
                "supported_ss": 0x95C8B8,
                "source_index": 0x95D088,
                "init_codec": 0x9608D0,
                "vendor_source_index": 0x9715F8,
                "provider_index": 0x7FFF9C,
                "type_eq": 0x95B384,
                "equal": 0x95ABDC,
                "vendor_type_eq": 0x970FA0,
                "hd_type_eq": 0x976B18,
                "hd_equal": 0x976C28,
                "ll_selectable": 0x64AF14,
                "ll_sep_index": 0x653778,
                "ll_msg_send": 0x9B8CB8,
            },
        ),
        "hal": ("libbluetooth_audio_session_aidl.so", {"validate": 0x2FF60}),
    },
    malloc_got=0xEA65E0,
    ll_veneers=(),
    word_patches=(
        (0x95C8F4, NOP, "enable-hd-slot"),
        (0x649638, b_ne(0x649638, 0x649724), "dispatch-private-adaptive-offload-builder"),
    ),
    defines={
        "native": (
            "-DS25_AOSP_HAL",
            "-DS25_NO_LL",
            "-DS25_HAL_ADAPTIVE_TYPE=8",
            "-DS25_ADDR_OPERATOR_NEW=0xe62c00",
            "-DS25_ADDR_APTX_CTOR=0x973614",
            "-DS25_ADDR_APTX_HD_CTOR=0x97787c",
            "-DS25_ADDR_APTX_HD_SET_CONFIG=0x97794c",
            "-DS25_ADDR_APTX_HD_SET_PEER=0x977e70",
            "-DS25_ADDR_FIND_PEER=0x654d68",
            "-DS25_ADDR_PEER_CACHE=0xf14368",
            "-DS25_ADDR_ALARM_NEW=0xdeef1c",
            "-DS25_ADDR_ALARM_SET=0xdefaec",
            "-DS25_ADDR_FREE_GOT=0xea6568",
            "-DS25_ADDR_PROPERTY_GET=0xdf5544",
            "-DS25_ADDR_CODEC_TYPE_META=0xeae890",
            "-DS25_ADDR_CODEC_TYPE_VECTOR=0xeae6c0",
            "-DS25_ADDR_BTA_AV_CO=0xf14360",
            "-DS25_ADDR_ACTIVE_PEER_CODEC=0x64ac98",
        ),
        "hal": ("-DS25_HAL_ADAPTIVE_TYPE=8",),
    },
    dispatch_check="s948u1_sites_check.py",
)

LAYOUTS = {layout.profile_id: layout for layout in (DZIF, S948U1_BZJA)}


def layout_for(profile):
    layout = LAYOUTS.get(profile.id)
    if layout is None:
        raise ValueError("No reviewed Samsung layout for profile " + profile.id)
    return layout


def build(profile):
    layout = layout_for(profile)
    BASE = inputs_dir()
    NDK = ndk_bin()
    options = native_options()
    BUILD.mkdir(parents=True, exist_ok=True)
    targets = {target["local_file"]: target for target in profile.targets}
    results = []
    for flavor, (name, functions) in layout.spec.items():
        reloc_adrps = {}
        original = BASE / name
        if hashlib.sha256(original.read_bytes()).hexdigest() != targets[name]["sha256"]:
            raise ValueError("immutable input mismatch")
        with original.open("rb") as f:
            old = ELFFile(f)
            assembly = [
                '.section .text.anchor,"ax",@progbits',
                ".global s25_anchor",
                ".hidden s25_anchor",
                "s25_anchor:",
                " bti c",
                " ret",
                ".text",
            ]
            for suffix, addr in functions.items():
                stolen = read_vaddr(old, addr, 8)
                first, second = struct.unpack("<II", stolen)
                if first == 0xD503245F and second & 0x9F000000 == 0x90000000:
                    imm = ((second >> 29) & 3) | (((second >> 5) & 0x7FFFF) << 2)
                    if imm & (1 << 20):
                        imm -= 1 << 21
                    reloc_adrps[suffix] = (((addr + 4) & ~0xFFF) + (imm << 12), second)
                else:
                    assert first == 0xD503233F, (suffix, hex(first))
                    assert second == 0xF800865E or second & 0xFFC003FF == 0xD10003FF, (
                        suffix,
                        hex(second),
                    )
                assembly += [
                    f".global tramp_{suffix}",
                    f".hidden tramp_{suffix}",
                    f"tramp_{suffix}:",
                    " bti c",
                    f" .inst 0x{first:08x}",
                    f" .inst 0x{second:08x}",
                    f" b 0x{addr + 8:x}",
                ]
            if flavor == "native":
                for veneer in layout.ll_veneers:
                    assembly += [
                        f".global s25_ll_dispatch_{veneer.suffix}",
                        f"s25_ll_dispatch_{veneer.suffix}:",
                        " cmp w8, #9",
                        " .inst 0x54000041",
                        " .inst 0x14000000",
                        f" cmp w8, #{veneer.replay_cmp}",
                        " .inst 0x14000000",
                    ]
            (BUILD / (flavor + "-tramp.S")).write_text("\n".join(assembly) + "\n")
        exe = BUILD / (flavor + "-payload.elf")
        cmd = [
            str(NDK / "clang++"),
            "--target=aarch64-linux-android34",
            "-std=c++17",
            "-I" + str(SRC),
            "-O2",
            "-ffreestanding",
            "-fno-builtin",
            "-fno-exceptions",
            "-fno-rtti",
            "-fno-stack-protector",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fvisibility=hidden",
            "-fPIC",
            "-mbranch-protection=standard",
            "-mno-outline-atomics",
            "-nostdlib",
            f"-DS25_MALLOC_GOT={layout.malloc_got:#x}",
        ]
        cmd += [
            "-DS25_RATE=" + str(options["RATE"]),
            "-DS25_MODE=" + str(options["MODE"]),
            "-DS25_R2=" + str(options["R2"]),
        ]
        if flavor == "hal":
            cmd += ["-DS25_HAL_ONLY"]
        cmd += list(layout.defines.get(flavor, ()))
        cmd += [
            str(DRIVER_SRC / "payload.cpp"),
            str(DRIVER_SRC / "ui.cpp"),
            str(DRIVER_SRC / "coexist.cpp"),
            str(SRC / "protocol.cpp"),
            str(SRC / "aptx_ll.cpp"),
            str(SRC / "aptx_ll_backend.cpp"),
            str(DRIVER_SRC / "aptx_ll_native.cpp"),
            str(DRIVER_SRC / "aptx_ll_switch.cpp"),
            str(DRIVER_SRC / "layout.cpp"),
            str(BUILD / (flavor + "-tramp.S")),
            "-Wl,-T," + str(DRIVER_SRC / "payload.ld"),
            "-Wl,-e,s25_anchor",
            "-Wl,--no-undefined",
            "-Wl,-Bsymbolic",
            "-Wl,--build-id=none",
            "-Wl,-z,max-page-size=16384",
            "-o",
            str(exe),
        ]
        subprocess.run(cmd, check=True)
        # AArch64 assembler numeric B operands are offsets; bind trampoline targets explicitly.
        eraw = bytearray(exe.read_bytes())
        with exe.open("rb") as ef:
            ee = ELFFile(io.BytesIO(ef.read()))
            ss = {s.name: s["st_value"] for s in ee.get_section_by_name(".symtab").iter_symbols()}
            for suffix, addr in functions.items():
                branch_va = ss["tramp_" + suffix] + 12
                for sg in ee.iter_segments():
                    if (
                        sg["p_type"] == "PT_LOAD"
                        and sg["p_vaddr"] <= branch_va < sg["p_vaddr"] + sg["p_filesz"]
                    ):
                        off = sg["p_offset"] + branch_va - sg["p_vaddr"]
                        eraw[off : off + 4] = branch(branch_va, addr + 8)
                        if suffix in reloc_adrps:
                            target, word = reloc_adrps[suffix]
                            delta = (target - ((branch_va - 4) & ~0xFFF)) >> 12
                            assert -(1 << 20) <= delta < (1 << 20)
                            imm = delta & 0x1FFFFF
                            word = (
                                (word & 0x9F00001F)
                                | ((imm & 3) << 29)
                                | (((imm >> 2) & 0x7FFFF) << 5)
                            )
                            eraw[off - 4 : off] = struct.pack("<I", word)
                        break
        if flavor == "native":
            for veneer in layout.ll_veneers:
                suffix, match, resume = veneer.suffix, veneer.match, veneer.resume
                addr = ss["s25_ll_dispatch_" + suffix]
                for sg in ee.iter_segments():
                    if (
                        sg["p_type"] == "PT_LOAD"
                        and sg["p_vaddr"] <= addr < sg["p_vaddr"] + sg["p_filesz"]
                    ):
                        offset = sg["p_offset"] + addr - sg["p_vaddr"]
                        eraw[offset + 8 : offset + 12] = branch(addr + 8, match)
                        eraw[offset + 16 : offset + 20] = branch(addr + 16, resume)
                        break
        exe.write_bytes(eraw)
        patches = []
        raw = bytearray(original.read_bytes())
        payload_segments = []
        with exe.open("rb") as f:
            e = ELFFile(f)
            syms = {s.name: s["st_value"] for s in e.get_section_by_name(".symtab").iter_symbols()}
            assert syms["s25_anchor"] == 0x2000000
            rels = [s for s in e.iter_sections() if s["sh_type"] in ["SHT_RELA", "SHT_REL"]]
            assert all(s.num_relocations() == 0 for s in rels), "payload has runtime relocations"
            payload_segments = [
                (dict(x.header), x.data())
                for x in e.iter_segments()
                if x["p_type"] == "PT_LOAD" and x["p_memsz"]
            ]
        with original.open("rb") as f:
            old = ELFFile(f)
            old_segments = [dict(x.header) for x in old.iter_segments()]

            def patch(addr, data):
                for x in old_segments:
                    if (
                        x["p_type"] == "PT_LOAD"
                        and x["p_vaddr"] <= addr
                        and addr + len(data) <= x["p_vaddr"] + x["p_filesz"]
                    ):
                        off = x["p_offset"] + addr - x["p_vaddr"]
                        raw[off : off + len(data)] = data
                        return
                raise RuntimeError("patch outside file-backed LOAD")

            for suffix, addr in functions.items():
                dest = syms["s25_" + suffix]
                data = struct.pack("<I", 0xD503245F) + branch(addr + 4, dest)
                patch(addr, data)
                patches.append(
                    {
                        "vaddr": hex(addr),
                        "replacement": data.hex(),
                        "hook": "s25_" + suffix,
                        "target": hex(dest),
                    }
                )
            if flavor == "native":
                for veneer in layout.ll_veneers:
                    addr, suffix = veneer.gate, veneer.suffix
                    data = branch(addr, syms["s25_ll_dispatch_" + suffix])
                    patch(addr, data)
                    patches.append(
                        {
                            "vaddr": hex(addr),
                            "replacement": data.hex(),
                            "hook": "dispatch-private-ll-" + suffix,
                        }
                    )
                for addr, word, hook in layout.word_patches:
                    data = struct.pack("<I", word)
                    patch(addr, data)
                    patches.append({"vaddr": hex(addr), "replacement": data.hex(), "hook": hook})

            # Append a readable program-header mapping; preserve all original virtual addresses.
            def align(n):
                return (n + 0x3FFF) & ~0x3FFF

            metadata_va = 0x1FF0000
            metadata_off = align(len(raw))
            raw.extend(bytes(metadata_off - len(raw)))
            count = len(old_segments) + 1 + len(payload_segments)
            table_size = count * 56
            metadata = {
                "p_type": 1,
                "p_flags": 4,
                "p_offset": metadata_off,
                "p_vaddr": metadata_va,
                "p_paddr": metadata_va,
                "p_filesz": table_size,
                "p_memsz": table_size,
                "p_align": 0x4000,
            }
            raw.extend(bytes(0x4000))
            extra = []
            for h, data in payload_segments:
                assert h["p_vaddr"] >= 0x2000000 and h["p_flags"] & 3 != 3
                off = align(len(raw))
                raw.extend(bytes(off - len(raw)))
                raw.extend(data)
                extra.append(
                    {
                        "p_type": 1,
                        "p_flags": h["p_flags"],
                        "p_offset": off,
                        "p_vaddr": h["p_vaddr"],
                        "p_paddr": h["p_vaddr"],
                        "p_filesz": len(data),
                        "p_memsz": h["p_memsz"],
                        "p_align": 0x4000,
                    }
                )
            ph_types = {
                "PT_NULL": 0,
                "PT_LOAD": 1,
                "PT_DYNAMIC": 2,
                "PT_INTERP": 3,
                "PT_NOTE": 4,
                "PT_SHLIB": 5,
                "PT_PHDR": 6,
                "PT_TLS": 7,
                "PT_GNU_EH_FRAME": 0x6474E550,
                "PT_GNU_STACK": 0x6474E551,
                "PT_GNU_RELRO": 0x6474E552,
                "PT_GNU_PROPERTY": 0x6474E553,
                "PT_AARCH64_MEMTAG_MTE": 0x70000002,
            }
            headers = []
            for h in old_segments:
                h["p_type"] = ph_types.get(h["p_type"], h["p_type"])
                if h["p_type"] == 6:
                    h.update(
                        p_offset=metadata_off,
                        p_vaddr=metadata_va,
                        p_paddr=metadata_va,
                        p_filesz=table_size,
                        p_memsz=table_size,
                    )
                headers.append(h)
            headers += [metadata] + extra
            table = b"".join(
                struct.pack(
                    "<IIQQQQQQ",
                    *[
                        h[k]
                        for k in [
                            "p_type",
                            "p_flags",
                            "p_offset",
                            "p_vaddr",
                            "p_paddr",
                            "p_filesz",
                            "p_memsz",
                            "p_align",
                        ]
                    ],
                )
                for h in headers
            )
            raw[metadata_off : metadata_off + len(table)] = table
            struct.pack_into("<Q", raw, 0x20, metadata_off)
            struct.pack_into("<H", raw, 0x38, count)
        out = BUILD / ("patched-" + name)
        out.write_bytes(raw)
        with out.open("rb") as f:
            check = ELFFile(f)
            for p in patches:
                assert read_vaddr(
                    check, int(p["vaddr"], 16), len(bytes.fromhex(p["replacement"]))
                ) == bytes.fromhex(p["replacement"])
            assert not any(
                x["p_flags"] & 3 == 3 for x in check.iter_segments() if x["p_type"] == "PT_LOAD"
            ), "W+X segment"
        results.append(
            {
                "flavor": flavor,
                "input": name,
                "input_sha256": targets[name]["sha256"],
                "output": out.name,
                "output_sha256": hashlib.sha256(out.read_bytes()).hexdigest(),
                "patches": patches,
                "symbols": {
                    k: hex(v)
                    for k, v in syms.items()
                    if k.startswith("s25_") or k.startswith("tramp_")
                },
            }
        )
        print(flavor, "built and verified", out.name)
    apk = BUILD / "patched-Bluetooth.apk"
    if apk.exists():
        results.append(
            {
                "flavor": "apk",
                "input": "Bluetooth.apk",
                "input_sha256": targets["Bluetooth.apk"]["sha256"],
                "output": apk.name,
                "output_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
                "patches": [
                    "Bluetooth codec aliases, preferred-profile completion and null active-device guards"
                ],
            }
        )
    runtime = BUILD / "runtime.prop"
    runtime.write_text(
        "persist.vendor.qcom.bluetooth.aptxadaptiver2_1_support="
        + ("true" if int(str(options["R2"])) >= 2 else "false")
        + "\n",
        newline="\n",  # read on the device by an exact shell `case` match
    )
    results.append(
        {
            "flavor": "properties",
            "output": runtime.name,
            "output_sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
            "r2": int(str(options["R2"])),
        }
    )
    for entry in results:
        entry["profile_id"] = profile.id
        entry["profile_fingerprint"] = profile.fingerprint
    (BUILD / "patch-manifest.json").write_text(json.dumps(results, indent=2) + "\n")
    return options


HOST_REQUIRES_JNI = True


def host_flags():
    return ["-DS25_R2=3", "-DS25_RATE=96000", "-DS25_MODE=4096"]


def host_cases(jni):
    return [
        ("ll_switch", [], []),
        ("aptx_ll", ["aptx_ll.cpp", "aptx_ll_backend.cpp"], []),
        ("ll_native_protocol", ["aptx_ll.cpp", "aptx_ll_native.cpp"], []),
        (
            "ll_ui_registration",
            ["ui.cpp", "protocol.cpp", "aptx_ll.cpp", "aptx_ll_native.cpp"],
            ["-DS25_UI_TEST_BASE", *jni],
        ),
        ("protocol", ["protocol.cpp"], []),
        ("peer_negotiation", ["protocol.cpp"], []),
        (
            "vendor",
            [
                "protocol.cpp",
                "payload.cpp",
                "layout.cpp",
                "aptx_ll.cpp",
                "aptx_ll_native.cpp",
            ],
            ["-DS25_MALLOC_GOT=0xea65e0"],
        ),
        (
            "ui_callback",
            ["ui.cpp", "protocol.cpp", "aptx_ll.cpp", "aptx_ll_native.cpp"],
            jni,
        ),
        ("layout_stability", ["layout.cpp", "protocol.cpp"], []),
    ]


def verify_dispatch(profile):
    import sys

    check = layout_for(profile).dispatch_check
    subprocess.run([sys.executable, str(ROOT / "tests" / check)], check=True)
