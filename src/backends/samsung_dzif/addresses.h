// SPDX-License-Identifier: GPL-2.0-only
// Stock libbluetooth_jni.so addresses called or read by the payload.
// Defaults are the verified SM-S931Z DZIF values; another profile's backend passes
// every one of these explicitly with -D (see tools/shizuka/backends/).
#pragma once

#ifndef S25_ADDR_OPERATOR_NEW
#define S25_ADDR_OPERATOR_NEW 0xe62580
#endif
#ifndef S25_ADDR_APTX_CTOR
#define S25_ADDR_APTX_CTOR 0x972f58
#endif
#ifndef S25_ADDR_APTX_HD_CTOR
#define S25_ADDR_APTX_HD_CTOR 0x9771c0
#endif
#ifndef S25_ADDR_APTX_HD_SET_CONFIG
#define S25_ADDR_APTX_HD_SET_CONFIG 0x977290
#endif
#ifndef S25_ADDR_APTX_HD_SET_PEER
#define S25_ADDR_APTX_HD_SET_PEER 0x9777b4
#endif
#ifndef S25_ADDR_FIND_PEER
#define S25_ADDR_FIND_PEER 0x654d68
#endif
#ifndef S25_ADDR_PEER_CACHE
#define S25_ADDR_PEER_CACHE 0xf14368
#endif
#ifndef S25_ADDR_ALARM_NEW
#define S25_ADDR_ALARM_NEW 0xdee85c
#endif
#ifndef S25_ADDR_ALARM_SET
#define S25_ADDR_ALARM_SET 0xdef42c
#endif
#ifndef S25_ADDR_FREE_GOT
#define S25_ADDR_FREE_GOT 0xea6568
#endif
#ifndef S25_ADDR_PROPERTY_GET
#define S25_ADDR_PROPERTY_GET 0xdf4e84
#endif
#ifndef S25_ADDR_CODEC_TYPE_META
#define S25_ADDR_CODEC_TYPE_META 0xeae890
#endif
#ifndef S25_ADDR_CODEC_TYPE_VECTOR
#define S25_ADDR_CODEC_TYPE_VECTOR 0xeae6c0
#endif

// HAL CodecConfiguration.codecType for aptX Adaptive: Samsung SEH AIDL uses 9,
// AOSP android.hardware.bluetooth.audio uses 8 (6 is LC3, 7 VENDOR, 9 OPUS).
#ifndef S25_HAL_ADAPTIVE_TYPE
#define S25_HAL_ADAPTIVE_TYPE 9
#endif

// S25_AOSP_HAL selects the AOSP audio-session path (getHalCodecConfiguration hook)
// instead of the Samsung seh_aidl converter hooks; it needs these two as well.
#ifdef S25_AOSP_HAL
#if !defined(S25_ADDR_BTA_AV_CO) || !defined(S25_ADDR_ACTIVE_PEER_CODEC)
#error "S25_AOSP_HAL requires S25_ADDR_BTA_AV_CO and S25_ADDR_ACTIVE_PEER_CODEC"
#endif
#endif
