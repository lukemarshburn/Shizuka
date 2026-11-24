// SPDX-License-Identifier: GPL-2.0-only
/** Private codec IDs and mode words are meaningful only for their verified backend. */
final class CodecPresentation {
    static final String SAMSUNG_DZIF = "samsung-sm-s931z-dzif";
    /** Same private Adaptive/Lossless IDs as DZIF; private aptX LL is not enabled. */
    static final String SAMSUNG_S948U1 = "samsung-sm-s948u1-bzja";

    private static boolean privateIds(String profile) {
        return SAMSUNG_DZIF.equals(profile) || SAMSUNG_S948U1.equals(profile);
    }

    static boolean losslessSelection(String profile, boolean le, int type) {
        return !le && privateIds(profile) && type == 12;
    }

    static String name(String profile, boolean le, int type, String systemName) {
        if (losslessSelection(profile, le, type)) return "aptX Lossless (selection)";
        if (!le && SAMSUNG_DZIF.equals(profile) && type == 13) return "aptX LL";
        return systemName == null || systemName.trim().isEmpty() ? "Codec " + type : systemName;
    }

    static String mode(String profile, int type, long value) {
        if (!privateIds(profile)) return null;
        if (type == 12) return "Lossless request";
        if (type != 7) return null;
        if (value == 4096) return "HQ";
        if (value == 8192) return "Low latency";
        return value == 0 ? "Default" : null;
    }
}
