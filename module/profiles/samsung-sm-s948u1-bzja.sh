# SPDX-License-Identifier: GPL-2.0-only
# Profile variables form the interface consumed by control.sh and qhs-nvm.sh.
# shellcheck disable=SC2034
# Backend: SM-S948U1 / S948U1UEU5BZJA (S26 Ultra). Mapped, not yet validated on device.
# The audio-session HAL is AOSP (android.hardware.bluetooth.audio), hosted by
# audiohalservice.qti (init service vendor.audio-hal-aidl); no SEH audio provider.
NATIVE=/apex/com.android.bt/lib64/libbluetooth_jni.so
HAL=/vendor/lib64/libbluetooth_audio_session_aidl.so
APK=/apex/com.android.bt/app/Bluetooth@CP2A.260605.016/Bluetooth.apk
OFFLOAD=/vendor/lib64/btaudio_offload_if.so
FRAMEWORK=/apex/com.android.bt/javalib/framework-bluetooth.jar
NATIVE_PAYLOAD=patched-libbluetooth_jni.so
HAL_PAYLOAD=patched-libbluetooth_audio_session_aidl.so
APK_PAYLOAD=patched-Bluetooth.apk
STOCK_TARGET_COUNT=5
AUDIO_HAL_SERVICE=vendor.audio-hal-aidl
AUDIO_HAL_FACTORY=android.hardware.bluetooth.audio.IBluetoothAudioProviderFactory/default
NATIVE_LABEL=u:object_r:system_lib_file:s0
HAL_LABEL=u:object_r:vendor_file:s0
APK_LABEL=u:object_r:system_file:s0
# Controller (ganges SoC) has no reviewed QHS NVM/firmware contract.
QHS_SUPPORTED=false

profile_target_allowed() {
 case "$1" in "$NATIVE"|"$HAL"|"$APK"|"$OFFLOAD"|"$FRAMEWORK") return 0;;*) return 1;;esac
}
profile_payload_allowed() {
 case "$1" in "$NATIVE_PAYLOAD"|"$HAL_PAYLOAD"|"$APK_PAYLOAD"|runtime.prop) return 0;;*) return 1;;esac
}
profile_managed_properties() {
 cat <<'PROPERTIES'
r21 persist.vendor.qcom.bluetooth.aptxadaptiver2_1_support present
dual-mode persist.bluetooth.enable_dual_mode_audio tracked
samsung-cap persist.bluetooth.samsung.a2dp_offload.cap present
snoop persist.bluetooth.btsnooplogmode present
aptx-voice bluetooth.hfp.codec_aptx_voice.enabled tracked
ad-priority bluetooth.a2dp.source.aptx_adaptive_priority.config tracked
hd-priority bluetooth.a2dp.source.aptx_hd_priority.config tracked
PROPERTIES
}
profile_apply_properties() {
 capability=$(cat "$STATE/samsung-cap") || return 1
 case "-$capability-" in *-aptx_hd-*) ;;*) capability="$capability-aptx_hd";;esac
 set_managed_property samsung-cap "$capability" || return 1
 # Android's codec properties win unless an extension override was explicitly selected.
 for setting in adaptive_priority aptx_hd_priority aptx_voice_enabled;do
  value=$(extension_value "$setting") || return 1
  [ "$value" != system ] || continue
  case "$setting" in adaptive_priority) saved=ad-priority;;aptx_hd_priority) saved=hd-priority;;aptx_voice_enabled) saved=aptx-voice;;esac
  set_managed_property "$saved" "$value" || return 1
 done
 case "$(cat "$MODDIR/payload/runtime.prop")" in
  persist.vendor.qcom.bluetooth.aptxadaptiver2_1_support=true) r21_value=true;;
  persist.vendor.qcom.bluetooth.aptxadaptiver2_1_support=false) r21_value=false;;
  *) fail 'unexpected runtime property payload';;
 esac
 set_managed_property r21 "$r21_value" || return 1
 if [ -f "$MODDIR/.enable-dual-mode" ];then set_managed_property dual-mode true;fi
}
profile_hal_ready() {
 [ -n "$1" ] && [ "$1" != "$2" ] || return 1
 grep -Fq "/${HAL##*/}" "/proc/$1/maps" 2>/dev/null || return 1
 "$BB" timeout 2 service call "$AUDIO_HAL_FACTORY" 1599098439 2>/dev/null | grep -q 'Result: Parcel'
}

# No DSP diagnostics, experiment or tuning provider is reviewed for this firmware;
# the optional profile_diagnostics_preflight / profile_*_experiments hooks are absent.
profile_tuning_availability() {
 cat <<'JSON'
{"schema":1,"runtime_apply_supported":false,"status":"unsupported","reason":"No DSP tuning provider is reviewed for this firmware.","scope":"additional_ttp","codec_selection_available":true}
JSON
}
