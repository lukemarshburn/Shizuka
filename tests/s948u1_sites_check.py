# SPDX-License-Identifier: GPL-2.0-only
"""SM-S948U1 BZJA layout check against the exact stock images (and patched outputs).

Every hook address must be the start of the named function in the image's own
MiniDebugInfo symbol table, with a prologue the trampoline builder accepts; every
in-function patch must find the stock instruction it was reviewed against; every
address the payload calls must be the named function. With patched outputs present
(the default when run from verify_dispatch), each hook entry must branch to its
payload and every other byte of the reviewed windows must be unchanged.

Usage: s948u1_sites_check.py [--stock-only]
"""

import io
import lzma
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs  # noqa: E402
from elftools.elf.elffile import ELFFile  # noqa: E402
from shizuka.backends.samsung_dzif import S948U1_BZJA as LAYOUT  # noqa: E402
from shizuka.profiles import load_profile  # noqa: E402
from shizuka.project import BUILD, digest, inputs_dir  # noqa: E402

PROFILE = "samsung-sm-s948u1-bzja"

# Function each hook must start: a distinctive substring of its mangled name.
NATIVE_HOOKS = {
    "prs_cfg": "avdt_msg_prs_cfg",
    "bld_cfg": "avdt_msg_bld_cfg",
    "hal_codec": "aidl4a2dp5codec24getHalCodecConfiguration",
    "specific": "A2dpCodecConfig22getCodecSpecificConfig",
    "vendor": "BTM_VendorSpecificCommand",
    "new_type": "newBluetoothCodecType",
    "supported": "getSupportedCodecTypesNative",
    "prepare": "prepareCodecPreferences",
    "callback": "bta2dp_audio_config_callback",
    "user": "A2dpCodecConfig18setCodecUserConfig",
    "factory": "A2dpCodecConfig11createCodec",
    "supported_ss": "A2dpCodecs18isSupportedCodecSs",
    "source_index": "_Z21A2DP_SourceCodecIndexPKh",
    "init_codec": "A2DP_InitCodecConfig",
    "vendor_source_index": "A2DP_VendorSourceCodecIndex",
    "provider_index": "a2dp8provider18source_codec_index",
    "type_eq": "_Z20A2DP_CodecTypeEqualsPKhS0_",
    "equal": "_Z16A2DP_CodecEqualsPKhS0_",
    "vendor_type_eq": "_Z26A2DP_VendorCodecTypeEqualsPKhS0_",
    "hd_type_eq": "A2DP_VendorCodecTypeEqualsAptxHd",
    "hd_equal": "A2DP_VendorCodecEqualsAptxHd",
    "ll_selectable": "UpdateAllSelectableSourceCodecs",
    "ll_sep_index": "bta_av_co_get_sep_info_idx",
    "ll_msg_send": "avdt_msg_send",
}
HAL_HOOKS = {"validate": "BluetoothAudioCodecs32IsOffloadCodecConfigurationValid"}

# Payload -D addresses: (define, mangled-name substring). GOT slots are checked separately.
CALLED = {
    "S25_ADDR_OPERATOR_NEW": None,  # hidden libc++ override; checked via createCodec below
    "S25_ADDR_APTX_CTOR": "A2dpCodecConfigAptxC1",
    "S25_ADDR_APTX_HD_CTOR": "A2dpCodecConfigAptxHdC1",
    "S25_ADDR_APTX_HD_SET_CONFIG": "A2dpCodecConfigAptxHd14setCodecConfig",
    "S25_ADDR_APTX_HD_SET_PEER": "A2dpCodecConfigAptxHd24setPeerCodecCapabilities",
    "S25_ADDR_FIND_PEER": "BtaAvCoPeerCache8FindPeer",
    "S25_ADDR_ALARM_NEW": "alarm_new_internal",
    "S25_ADDR_ALARM_SET": "alarm_set_internal",
    "S25_ADDR_PROPERTY_GET": "osi_property_get",
    "S25_ADDR_ACTIVE_PEER_CODEC": "BtaAvCo25GetActivePeerCurrentCodec",
}

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


class Image:
    def __init__(self, path, symbols=True):
        self.raw = Path(path).read_bytes()
        self.elf = ELFFile(io.BytesIO(self.raw))
        self.funcs = {}
        if symbols:
            mini = ELFFile(
                io.BytesIO(lzma.decompress(self.elf.get_section_by_name(".gnu_debugdata").data()))
            )
            for table in (mini.get_section_by_name(".symtab"), self.elf.get_section_by_name(".dynsym")):
                for s in table.iter_symbols():
                    if s["st_info"]["type"] == "STT_FUNC" and s["st_value"]:
                        self.funcs.setdefault(s["st_value"], s.name)

    def read(self, addr, size):
        for seg in self.elf.iter_segments():
            if seg["p_type"] == "PT_LOAD" and seg["p_vaddr"] <= addr and addr + size <= seg["p_vaddr"] + seg["p_filesz"]:
                off = seg["p_offset"] + addr - seg["p_vaddr"]
                return self.raw[off : off + size]
        raise AssertionError(f"{addr:#x} outside file-backed LOAD")

    def word(self, addr):
        return struct.unpack("<I", self.read(addr, 4))[0]

    def ins(self, addr):
        return next(md.disasm(self.read(addr, 4), addr))

    def got(self, name):
        for sec in self.elf.iter_sections():
            if sec["sh_type"] in ("SHT_RELA", "SHT_REL"):
                symtab = self.elf.get_section(sec["sh_link"])
                for r in sec.iter_relocations():
                    if r["r_info_sym"] and symtab.get_symbol(r["r_info_sym"]).name == name:
                        return r["r_offset"]
        raise AssertionError("no relocation for " + name)


def fail(message):
    raise AssertionError(message)


def check_hook(img, suffix, addr, expected):
    name = img.funcs.get(addr)
    if not name or expected not in name:
        fail(f"{suffix}: {addr:#x} is {name!r}, expected *{expected}*")
    first, second = struct.unpack("<II", img.read(addr, 8))
    bti_adrp = first == 0xD503245F and second & 0x9F000000 == 0x90000000
    pac = first == 0xD503233F and (second == 0xF800865E or second & 0xFFC003FF == 0xD10003FF)
    if not (bti_adrp or pac):
        fail(f"{suffix}: unsupported prologue {first:08x} {second:08x}")


def codec_type_value(img, wanted):
    """Value of aidl CodecType `wanted` from the stock ToString<CodecType> jump table.

    Only names the compiler loads from .rodata are matched (APTX_ADAPTIVE is one);
    short names built from immediates (LC3, SBC) are not decoded.
    """
    start = next(
        a
        for a, n in img.funcs.items()
        if "internal8ToStringIN4aidl7android8hardware9bluetooth5audio9CodecType" in n
    )
    code = list(md.disasm(img.read(start, 40), start))
    ops = [(x.mnemonic, x.op_str) for x in code]
    if ops[2][0] != "cmp" or ops[4][0] != "adrp" or ops[6][0] != "adr" or ops[9][0] != "br":
        fail("ToString<CodecType> dispatch shape changed")
    count = int(ops[2][1].split("#")[1], 0) + 1
    table = int(ops[4][1].split("#")[1], 16) + int(ops[5][1].split("#")[1], 16)
    base = int(ops[6][1].split("#")[1], 16)
    for value, offset in enumerate(img.read(table, count)):
        case = base + offset * 4
        text = b""
        for x in md.disasm(img.read(case, 48), case):
            if x.mnemonic == "adrp":
                page = int(x.op_str.split("#")[1], 16)
            elif x.mnemonic == "add" and x.op_str.startswith("x10, x10"):
                text = img.read(page + int(x.op_str.split("#")[1], 16), 32).split(b"\0")[0]
                break
            elif x.mnemonic in ("ret", "b"):
                break
        if text == wanted.encode():
            return value
    fail(f"CodecType {wanted} not found")


def defines():
    out = {}
    for flag in LAYOUT.defines["native"]:
        key, _, value = flag[2:].partition("=")
        out[key] = int(value, 0) if value else True
    return out


def stock_checks(jni, hal):
    native_lib, native_hooks = LAYOUT.spec["native"]
    hal_lib, hal_hooks = LAYOUT.spec["hal"]
    if set(native_hooks) != set(NATIVE_HOOKS) or set(hal_hooks) != set(HAL_HOOKS):
        fail("layout hook set differs from the reviewed list")
    for suffix, addr in native_hooks.items():
        check_hook(jni, suffix, addr, NATIVE_HOOKS[suffix])
    for suffix, addr in hal_hooks.items():
        check_hook(hal, suffix, addr, HAL_HOOKS[suffix])

    # In-function patch sites, against their reviewed stock instructions.
    sites = {addr: hook for addr, _, hook in LAYOUT.word_patches}
    if set(sites.values()) != {"enable-hd-slot", "dispatch-private-adaptive-offload-builder"}:
        fail("unexpected word patch set")
    hd = next(a for a, h in sites.items() if h == "enable-hd-slot")
    if hd != native_hooks["supported_ss"] + 0x3C or jni.ins(hd).mnemonic != "b.eq":
        fail("enable-hd-slot site is not isSupportedCodecSs+0x3c b.eq")
    off = next(a for a, h in sites.items() if h == "dispatch-private-adaptive-offload-builder")
    gate = jni.ins(off - 0x1C)
    if (gate.mnemonic, gate.op_str) != ("cmp", "w8, #2") or jni.ins(off).mnemonic != "b.ne":
        fail("offload builder window differs from DZIF shape")
    word = next(w for a, w, h in LAYOUT.word_patches if a == off)
    dest = off + (((word >> 5) & 0x7FFFF) << 2)
    if (jni.ins(dest).mnemonic, jni.ins(dest).op_str) != ("mov", "w27, #8"):
        fail("offload builder Adaptive target is not the HD framing arm")
    if not jni.funcs.get(max(a for a in jni.funcs if a <= off), "").startswith("_Z18bta_av_offload_req"):
        fail("offload builder site is outside bta_av_offload_req")
    # LL is disabled: the init bound stays at 9 (indices 0..8), never patched.
    init = 0x95ED90
    if (jni.ins(init).mnemonic, jni.ins(init).op_str) != ("cmp", "w23, #9") or init in sites:
        fail("source init bound changed or patched")
    if LAYOUT.ll_veneers:
        fail("LL veneers must stay disabled on the AOSP-HAL layout")

    # Absolute addresses the payload calls or reads.
    d = defines()
    for key in ("S25_AOSP_HAL", "S25_NO_LL"):
        if d.get(key) is not True:
            fail(key + " must be defined")
    adaptive = codec_type_value(jni, "APTX_ADAPTIVE")
    if d["S25_HAL_ADAPTIVE_TYPE"] != adaptive:
        fail(f"S25_HAL_ADAPTIVE_TYPE must be CodecType::APTX_ADAPTIVE ({adaptive})")
    if LAYOUT.defines["hal"] != (f"-DS25_HAL_ADAPTIVE_TYPE={adaptive}",):
        fail("HAL flavor must use the same CodecType::APTX_ADAPTIVE")
    for key, expected in CALLED.items():
        if expected and expected not in jni.funcs.get(d[key], ""):
            fail(f"{key}={d[key]:#x} is {jni.funcs.get(d[key])!r}")
    if d["S25_ADDR_FREE_GOT"] != jni.got("free") or LAYOUT.malloc_got != jni.got("malloc"):
        fail("malloc/free GOT slots moved")
    # createCodec allocates 0x1e0 then constructs aptX HD: operator new and object size.
    factory = native_hooks["factory"]
    code = list(md.disasm(jni.read(factory, 488), factory))

    def call(x):
        return int(x.op_str[1:], 16) if x.mnemonic == "bl" else None

    ctor = [i for i, x in enumerate(code) if call(x) == d["S25_ADDR_APTX_HD_CTOR"]]
    if len(ctor) != 1:
        fail("aptX HD construction not found once in createCodec")
    alloc = [i for i in range(ctor[0] - 4, ctor[0]) if call(code[i]) is not None]
    if (
        len(alloc) != 1
        or call(code[alloc[0]]) != d["S25_ADDR_OPERATOR_NEW"]
        or (code[alloc[0] - 1].mnemonic, code[alloc[0] - 1].op_str) != ("mov", "w0, #0x1e0")
    ):
        fail("aptX HD allocation differs (operator new or 0x1e0 size)")
    # Globals: GetActivePeerCurrentCodec(this) callers pass BtaAvCo; its +8 is the peer cache.
    if d["S25_ADDR_PEER_CACHE"] != d["S25_ADDR_BTA_AV_CO"] + 8:
        fail("peer cache is not BtaAvCo+8")
    caller = list(md.disasm(jni.read(0x649598, 12), 0x649598))
    page = int(caller[0].op_str.split("#")[1], 16) + int(caller[1].op_str.split("#")[1], 16)
    if page != d["S25_ADDR_BTA_AV_CO"] or int(caller[2].op_str[1:], 16) != d["S25_ADDR_ACTIVE_PEER_CODEC"]:
        fail("bta_av_offload_req no longer passes BtaAvCo to GetActivePeerCurrentCodec")

    # HAL validator: session guard (2 / 11); its codecType switch has cases
    # 1..5, 7 (VENDOR, Samsung SSC) and 9 (OPUS) only, so APTX_ADAPTIVE falls through.
    v = hal_hooks["validate"]
    body = [(x.mnemonic, x.op_str) for x in md.disasm(hal.read(v, 0x120), v)]
    for needed in (("cmp", "w8, #2"), ("cmp", "w8, #0xb"), ("cmp", "w8, #6")):
        if needed not in body:
            fail(f"validator lacks {needed}")
    gt6 = body.index(("cmp", "w8, #6"))
    if body[gt6 + 1][0] != "b.gt" or ("cmp", "w8, #5") not in body[gt6 : gt6 + 6]:
        fail("validator codecType switch changed")
    if ("cmp", f"w8, #{adaptive}") in body:
        fail("stock validator already handles APTX_ADAPTIVE; the hook is unreviewed")
    print("stock: 24 JNI hooks, 1 HAL hook, 2 word patches, payload addresses verified")


def patched_checks(jni, hal):
    for lib, (name, hooks), stock in (
        ("native", LAYOUT.spec["native"], jni),
        ("hal", LAYOUT.spec["hal"], hal),
    ):
        out = Image(BUILD / ("patched-" + name), symbols=False)
        for suffix, addr in hooks.items():
            if out.word(addr) != 0xD503245F or out.ins(addr + 4).mnemonic != "b":
                fail(f"{lib} {suffix}: entry is not bti c; b payload")
            if int(out.ins(addr + 4).op_str[1:], 16) < 0x2000000:
                fail(f"{lib} {suffix}: branch does not reach the payload segment")
            reviewed = {a for a, _, _ in LAYOUT.word_patches} if lib == "native" else set()
            for at in range(addr + 8, addr + 64, 4):
                if at not in reviewed and out.word(at) != stock.word(at):
                    fail(f"{lib} {suffix}: {at:#x} after the stolen prologue changed")
        if lib == "native":
            for addr, word, hook in LAYOUT.word_patches:
                if out.word(addr) != word:
                    fail(hook + " not applied")
                for delta in (-8, -4, 4, 8):
                    if out.word(addr + delta) != stock.word(addr + delta):
                        fail(hook + " neighbours changed")
    print("patched: hook entries and patch windows verified")


def main():
    profile = load_profile(PROFILE)
    base = inputs_dir()
    for target in profile.targets:
        if digest(base / target["local_file"]) != target["sha256"]:
            fail("stock input mismatch: " + target["local_file"])
    jni = Image(base / LAYOUT.spec["native"][0])
    hal = Image(base / LAYOUT.spec["hal"][0])
    stock_checks(jni, hal)
    if "--stock-only" not in sys.argv[1:]:
        patched_checks(jni, hal)


if __name__ == "__main__":
    main()
