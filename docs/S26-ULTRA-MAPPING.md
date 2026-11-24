# SM-S948U1 (S26 Ultra) offset mapping — working notes

Status: **static mapping plus a read-only device check of the HAL.** Nothing here has been built, patched, or run on
the phone. Per [PORTING.md](PORTING.md), matching addresses do not establish
compatibility; each entry still needs the dispatch/host checks and on-device
validation.

## Target

| | |
| --- | --- |
| Model / build | SM-S948U1, `S948U1UEU5BZJA`, SoC SM8850 |
| Bluetooth APEX | `com.android.bt`, `Bluetooth@CP2A.260605.016` (same folder name as DZIF) |
| Inputs | `inputs/SMS948U1-S948U1UEU5BZJA/` via `tools/pull_stock_inputs.ps1` |

| File | SHA-256 | vs. DZIF |
| --- | --- | --- |
| `libbluetooth_jni.so` | `8040446777e75c99c2f975e7c090900d048aab78e55a5a8fca67dca1ad4c96a8` | different build, near-identical layout |
| `Bluetooth.apk` | `464e86dbd9388e1654abc7c0fd16eca8ee6a24a3862b59b3b8a067e989eab4ac` | different |
| `framework-bluetooth.jar` | `4abab23a398052c624cb888cb90c2935a0635ffebdaee87a835146e09b49fa96` | **identical** |
| `btaudio_offload_if.so` | `b61f20d20e660b199a877e87bcdcc9e0cb16eee3ce49bdc1c281f7b1211798d4` | different |
| `libbluetooth_audio_session_aidl.so` | `344ab7bad8ee9a7a21312fb329871c2e7c0ea8f278347d1aa8ffb05f20c790d3` | replaces `libsehbluetooth_audio_session_aidl.so` (absent) |
| `libbluetooth_audio_session_aidl_qti.so` | `75bd66ee44ca21eecbe365b11f71752ed2d2a12117239d7365ce5dbb4716b972` | Qualcomm variant |
| `aptx_adaptive_enc_module.so.1` | `c4c16abdfba75a7f12740660402ddecdbe95bd3a13589219a4ab1b219a90df69` | Hexagon DSP encoder |

## Method

S26 libraries carry `.gnu_debugdata` (MiniDebugInfo), giving local function
names. Each DZIF hook address was checked against S26 symbols; the JNI library
differs from DZIF only by a few constant per-region shifts. Every function hook
starts with a prologue the existing trampoline builder accepts
(`paciasp; str x30,[x18],#8` / `sub sp`, or `bti c; adrp`).

## `libbluetooth_jni.so` function hooks (25/25 mapped)

| Hook | DZIF | S26 | Shift | S26 symbol |
| --- | --- | --- | --- | --- |
| `supported` | `0x3F5DE4` | `0x3F5DE4` | 0 | `getSupportedCodecTypesNative` |
| `prepare` | `0x3F78C4` | `0x3F78C4` | 0 | `prepareCodecPreferences` |
| `callback` | `0x3F8228` | `0x3F8228` | 0 | `bta2dp_audio_config_callback` |
| `new_type` | `0x3FB8E4` | `0x3FB8E4` | 0 | `newBluetoothCodecType` |
| `ll_selectable` | `0x64AF14` | `0x64AF14` | 0 | `BtaAvCo::UpdateAllSelectableSourceCodecs` |
| `ll_sep_index` | `0x653778` | `0x653778` | 0 | `bta_av_co_get_sep_info_idx` |
| `provider_index` | `0x8000BC` | `0x7FFF9C` | −0x120 | `a2dp::provider::source_codec_index` (`bti c; adrp` → ADRP relocation path) |
| `to_hal` | `0x873758` | `0x8739A8` | +0x250 | `seh_aidl::…::A2dpAptxToHalConfig` |
| `enabled` | `0x874E50` | `0x8750A0` | +0x250 | `seh_aidl::…::IsCodecOffloadingEnabled` |
| `specific` | `0x959F48` | `0x95A604` | +0x6BC | `A2dpCodecConfig::getCodecSpecificConfig` |
| `factory` | `0x959C70` | `0x95A32C` | +0x6BC | `A2dpCodecConfig::createCodec` |
| `user` | `0x95A330` | `0x95A9EC` | +0x6BC | `A2dpCodecConfig::setCodecUserConfig` |
| `equal` | `0x95A520` | `0x95ABDC` | +0x6BC | `A2DP_CodecEquals` |
| `type_eq` | `0x95ACC8` | `0x95B384` | +0x6BC | `A2DP_CodecTypeEquals` |
| `supported_ss` | `0x95C1FC` | `0x95C8B8` | +0x6BC | `A2dpCodecs::isSupportedCodecSs` |
| `source_index` | `0x95C9CC` | `0x95D088` | +0x6BC | `A2DP_SourceCodecIndex` |
| `init_codec` | `0x960214` | `0x9608D0` | +0x6BC | `A2DP_InitCodecConfig` |
| `vendor_type_eq` | `0x9708E4` | `0x970FA0` | +0x6BC | `A2DP_VendorCodecTypeEquals` |
| `vendor_source_index` | `0x970F3C` | `0x9715F8` | +0x6BC | `A2DP_VendorSourceCodecIndex` |
| `hd_type_eq` | `0x97645C` | `0x976B18` | +0x6BC | `A2DP_VendorCodecTypeEqualsAptxHd` |
| `hd_equal` | `0x97656C` | `0x976C28` | +0x6BC | `A2DP_VendorCodecEqualsAptxHd` |
| `ll_msg_send` | `0x9B85FC` | `0x9B8CB8` | +0x6BC | `avdt_msg_send` |
| `bld_cfg` | `0x9B9DEC` | `0x9BA4A8` | +0x6BC | `avdt_msg_bld_cfg` |
| `prs_cfg` | `0x9BA5E4` | `0x9BACA0` | +0x6BC | `avdt_msg_prs_cfg` |
| `vendor` | `0x9E9DCC` | `0x9EA488` | +0x6BC | `BTM_VendorSpecificCommand` |

## In-function patch sites

| Patch | DZIF | S26 | Check |
| --- | --- | --- | --- |
| HAL dispatch gate (`cmp w8,#5`) | `0x8561C4` | `0x856414` | in `seh_aidl::setup_codec`; `b.gt` follows |
| HAL resume / match | `0x8561C8` / `0x8561E0` | `0x856418` / `0x856430` | match is the 2/3 aptX converter arm |
| HAL private-5 branch (`b.ne`) | `0x856458` | `0x8566A8` | gate+0x294, same as DZIF |
| SEH `peerMtu` reference (comment only) | `0x8564D4` | `0x856724` | not yet re-verified |
| Offload gate (`cmp w8,#2`) | `0x64961C` | `0x64961C` | `bta_av_offload_req`; `b.le` at +4 |
| Offload private-5 (`b.ne`) / target | `0x649638` / `0x649724` | same | target `mov w27,#8`; match `0x649658` `mov w27,#4` |
| Source init bound (`cmp w23,#9`) | `0x95E6D4` | `0x95ED90` | `A2dpCodecs::init` |
| Enable HD slot (NOP) | `0x95C238` | `0x95C8F4` | `isSupportedCodecSs`+0x3C, `b.eq` |

## Absolute addresses used by the payload sources

| Use | DZIF | S26 | Evidence |
| --- | --- | --- | --- |
| `S25_MALLOC_GOT` | `0xEA65E0` | `0xEA65E0` | `.rela.plt` slot for `malloc` |
| `free` GOT (`aptx_ll_switch.cpp`) | `0xEA6568` | `0xEA6568` | `.rela.plt` slot for `free` |
| `operator new` | `0xE62580` | `0xE62C00` | `createCodec` calls it with 0x1E0 before each ctor |
| `A2dpCodecConfigAptx` ctor | `0x972F58` | `0x973614` | symbol |
| `A2dpCodecConfigAptxHd` ctor | `0x9771C0` | `0x97787C` | symbol; `createCodec` allocation size still 0x1E0 |
| `AptxHd::setCodecConfig` | `0x977290` | `0x97794C` | symbol |
| `AptxHd::setPeerCodecCapabilities` | `0x9777B4` | `0x977E70` | symbol |
| `BtaAvCoPeerCache::FindPeer` | `0x654D68` | `0x654D68` | symbol |
| `alarm_new_internal` | `0xDEE85C` | `0xDEEF1C` | symbol (+0x6C0) |
| `alarm_set_internal` | `0xDEF42C` | `0xDEFAEC` | symbol (+0x6C0) |
| `osi_property_get` | `0xDF4E84` | `0xDF5544` | symbol (+0x6C0) |
| peer cache global | `0xF14368` | `0xF14368` | loaded by `bta_av_co_get_sep_info_idx` |
| codec-type vector | `0xEAE6C0` | `0xEAE6C0` | `getSupportedCodecTypesNative`, `newBluetoothCodecType` |
| JNI codec-type metadata | `0xEAE890` | `0xEAE890` | same two functions |

Struct field offsets (`+0x1A0`, `+0x1AD`, `+0x110`, …) are assumed unchanged
because the codec object size and constructors match; not yet verified per field.

## Audio-session HAL: AOSP path only (confirmed on device)

Checked on the phone (2026-11-24, root shell):

- `service list` registers only `android.hardware.bluetooth.audio.IBluetoothAudioProviderFactory/default`.
  No `ISehBluetoothAudioProviderFactory`; the only SEH Bluetooth service is
  `vendor.samsung.hardware.bluetooth.ISehBluetooth/default` (controller, not audio).
- The provider runs in `audiohalservice.qti`, which maps
  `libbluetooth_audio_session_aidl.so` (not the `_qti` variant),
  `android.hardware.bluetooth.audio-impl.so` and `btaudio_offload_if.so`.

Consequence: the JNI takes `bluetooth::audio::aidl`, so the three `seh_aidl`
entries above (`to_hal`, `enabled`, HAL dispatch gate/branch) are mapped but
**never execute**. They move to the AOSP path:

| DZIF hook | S26 AOSP replacement | Address | Prologue | Note |
| --- | --- | --- | --- | --- |
| `to_hal` | `aidl::a2dp::codec::getHalCodecConfiguration(const ahal_codec_configuration&, CodecConfiguration*)` | `0x8499C4` | `paciasp; str x30,[x18],#8` | different input: config, not codec object; all per-codec converters inlined |
| `enabled` | `aidl::a2dp::codec::(anon)::IsCodecOffloadingEnabled(const CodecConfiguration&)` | `0x84AD28` | `paciasp; str x30,[x18],#8` | same role |
| HAL dispatch | `aidl::a2dp::setup_codec` | `0x800D74` | — | likely unneeded if `getHalCodecConfiguration` is hooked |
| `validate` (HAL) | `BluetoothAudioCodecs::IsOffloadCodecConfigurationValid(const SessionType&, const CodecConfiguration&)` in `libbluetooth_audio_session_aidl.so` | `0x2FF60` | `paciasp; sub sp,sp,#0x70` | see below |

### HAL validator

Stock logic: `session == 2 || session == 11` (the same guard `s25_validate`
replays), then a switch on `CodecConfiguration.codecType` (resolved through PLT):

| codecType | Validator |
| --- | --- |
| 1 | SBC |
| 2 | AAC |
| 3 | aptX |
| 4 | aptX HD |
| 5 | LDAC |
| 6 (LC3) | none → returns false |
| 7 (VENDOR) | Samsung SSC |
| **8 (APTX_ADAPTIVE)** | **none → returns false** |
| 9 (OPUS) | Opus |

AOSP `CodecType::APTX_ADAPTIVE` is 8 (read from the stock `ToString<CodecType>` table,
which `s948u1_sites_check.py` decodes). The hook is the DZIF `validate` with the
codec-type constant changed from SEH `9` to AOSP `8`. A first trial used 6 (LC3)
by mistake: the HAL got an LC3-typed config carrying aptX Adaptive parameters and
no audio played; the module rolled back cleanly.

### Layout compatibility (from `writeToParcel` in the S26 JNI)

- `AptxAdaptiveConfiguration` (AOSP) and `SehAptxAdaptiveConfiguration` read
  identical offsets (`0, 4, 8(u8), 0xC, buffering, ttp, 0x1C, 0x20, vector@0x28`),
  so `s25::AdaptiveConfig` (`src/layout.h`) is reusable.
- `CodecConfiguration` vs `SehCodecConfiguration`: codec type at `+0`, `+0xC` byte
  field identical; `CodecSpecific` variant tag at union `+0x48` in both, i.e.
  `+0x58` overall, where the payload already writes it.
- Still to confirm: the AOSP `CodecSpecific` alternative index for
  `aptxAdaptiveConfig` (payload writes 4 for SEH) and the remaining outer fields.

### Downstream

`btaudio_offload_if.so` contains a full aptX Adaptive conversion (mode, MTU, sink
caps, min/max sink buffering HQ/LL/TWS, input mode, fade duration), and
`android.hardware.bluetooth.audio-impl.so` knows `APTX_ADAPTIVE` and
`aptxAdaptiveConfig`. A HAL-accepted Adaptive config therefore has a DSP route;
not tested.

## Port status (2026-11-24)

Native payloads **build** with NDK 26.1 (`tools/build.py`, profile
`samsung-sm-s948u1-bzja`) and pass the build's own checks plus
`tests/s948u1_sites_check.py` on the patched outputs. The compiled `s25_hal_codec`
resolves BtaAvCo `0xF14360`, `GetActivePeerCurrentCodec` `0x64AC98` and the malloc
GOT `0xEA65E0`; its trampoline replays `paciasp; str x30` and resumes at `0x8499CC`.
Shared host suites pass on Windows (llvm-mingw, ASan/UBSan; `vendor` crashes under
Windows ASan on unmodified HEAD too, and passes without sanitizers). Nothing has run
on the phone, and the AOSP-path hook has no host emulation test yet.

| Piece | Where |
| --- | --- |
| Profile | `profiles/samsung-sm-s948u1-bzja/profile.json` (driver `samsung-dzif`, id `sm-s948u1-bzja-aptx-experiment`) |
| Layout | `S948U1_BZJA` in `tools/shizuka/backends/samsung_dzif.py`; DZIF moved into the same `Layout` form with unchanged values |
| Payload addresses | `src/backends/samsung_dzif/addresses.h` (DZIF defaults; S26 passes `-D` overrides) |
| AOSP HAL hook | `s25_hal_codec` in `payload.cpp` (`S25_AOSP_HAL`), shared `finish_adaptive` with the SEH `s25_to_hal`; `S25_HAL_ADAPTIVE_TYPE=8` |
| LL disabled | `S25_NO_LL`: no slot-9 init patch, no LL veneers, LL not advertised; LL hooks stay installed but inert |
| Runtime | `module/profiles/samsung-sm-s948u1-bzja.sh` (AOSP factory readiness, QHS off, no DSP experiments) |
| Site check | `tests/s948u1_sites_check.py` (`verify_dispatch`); `--stock-only` passes against the pulled inputs |

Hook set: 24 JNI hooks (the 25 mapped, minus `to_hal`/`enabled`, plus `hal_codec`),
1 HAL hook, 2 word patches (`enable-hd-slot`, offload builder Adaptive branch).

## Bluetooth.apk patches

`profiles/samsung-sm-s948u1-bzja/bluetooth-apk.json` is generated by
`tools/port_apk_patches.py` from the DZIF definitions: inserted text is reused byte for
byte, and every edit is re-anchored by an explicit line shift with the reviewed stock
text asserted around the anchor. Five files keep the DZIF line numbers; in
`AdapterService.smali` every anchor is 83 lines earlier.

The `s25CompletePreferredRequest` call keeps the DZIF position (before `:goto_1` in
`sendPreferredAudioProfilesCallbackToApps`, i.e. the `RemoteException` path). This
is inferred from the consistent −83 shift at both other anchors in that file, since
DZIF stores no deleted/context text. It reproduces DZIF behaviour rather than
changing it; review if that call was meant to run after `finishBroadcast()`.

apktool writes the platform line separator, so smali digests are taken over LF text
(`build_android.py` normalizes before checking). The patched APK keeps the stock
`AndroidManifest.xml` and `resources.arsc`; only `classes.dex` changes. The three
APK checks pass against it (486 HQ-predicate, 2592 LE-route, 20736 handoff cases).

## Remaining work

1. Toolchain: installed (JDK 17, SDK 35 / build-tools 35.0.0, NDK 26.1, apktool 3.0.3,
   llvm-mingw).
2. `bluetooth-apk.json`: done (see above). All four payloads build.
3. An emulation check of `s25_hal_codec` (DZIF has `dispatch_emulation_check.py`).
4. Packaging: full `verify_offline.py`, the companion app (Gradle fetches its
   dependencies) and `package.py`.
5. On-device: activation trial with rollback, reboot, HAL readiness, listening test.
6. Not ported: private aptX LL, QHS, DSP diagnostics/TTP.
