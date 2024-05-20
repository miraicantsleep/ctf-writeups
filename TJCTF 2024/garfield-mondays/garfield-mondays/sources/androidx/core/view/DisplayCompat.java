package androidx.core.view;

import android.app.UiModeManager;
import android.content.Context;
import android.graphics.Point;
import android.os.Build;
import android.text.TextUtils;
import android.view.Display;
import androidx.core.util.Preconditions;
import java.lang.reflect.Method;
/* loaded from: classes.dex */
public final class DisplayCompat {
    private static final int DISPLAY_SIZE_4K_HEIGHT = 2160;
    private static final int DISPLAY_SIZE_4K_WIDTH = 3840;

    private DisplayCompat() {
    }

    public static ModeCompat getMode(Context context, Display display) {
        return Api23Impl.getMode(context, display);
    }

    private static Point getDisplaySize(Context context, Display display) {
        Point displaySize = getCurrentDisplaySizeFromWorkarounds(context, display);
        if (displaySize != null) {
            return displaySize;
        }
        Point displaySize2 = new Point();
        Api17Impl.getRealSize(display, displaySize2);
        return displaySize2;
    }

    public static ModeCompat[] getSupportedModes(Context context, Display display) {
        return Api23Impl.getSupportedModes(context, display);
    }

    private static Point parseDisplaySize(String displaySize) throws NumberFormatException {
        String[] displaySizeParts = displaySize.trim().split("x", -1);
        if (displaySizeParts.length == 2) {
            int width = Integer.parseInt(displaySizeParts[0]);
            int height = Integer.parseInt(displaySizeParts[1]);
            if (width > 0 && height > 0) {
                return new Point(width, height);
            }
        }
        throw new NumberFormatException();
    }

    private static String getSystemProperty(String name) {
        try {
            Class<?> systemProperties = Class.forName("android.os.SystemProperties");
            Method getMethod = systemProperties.getMethod("get", String.class);
            return (String) getMethod.invoke(systemProperties, name);
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean isTv(Context context) {
        UiModeManager uiModeManager = (UiModeManager) context.getSystemService("uimode");
        return uiModeManager != null && uiModeManager.getCurrentModeType() == 4;
    }

    private static Point parsePhysicalDisplaySizeFromSystemProperties(String property, Display display) {
        if (display.getDisplayId() != 0) {
            return null;
        }
        String displaySize = getSystemProperty(property);
        if (TextUtils.isEmpty(displaySize) || displaySize == null) {
            return null;
        }
        try {
            return parseDisplaySize(displaySize);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    static Point getCurrentDisplaySizeFromWorkarounds(Context context, Display display) {
        Point displaySize;
        if (Build.VERSION.SDK_INT < 28) {
            displaySize = parsePhysicalDisplaySizeFromSystemProperties("sys.display-size", display);
        } else {
            displaySize = parsePhysicalDisplaySizeFromSystemProperties("vendor.display-size", display);
        }
        if (displaySize != null) {
            return displaySize;
        }
        if (isSonyBravia4kTv(context) && isCurrentModeTheLargestMode(display)) {
            return new Point(DISPLAY_SIZE_4K_WIDTH, DISPLAY_SIZE_4K_HEIGHT);
        }
        return null;
    }

    private static boolean isSonyBravia4kTv(Context context) {
        return isTv(context) && "Sony".equals(Build.MANUFACTURER) && Build.MODEL.startsWith("BRAVIA") && context.getPackageManager().hasSystemFeature("com.sony.dtv.hardware.panel.qfhd");
    }

    static boolean isCurrentModeTheLargestMode(Display display) {
        return Api23Impl.isCurrentModeTheLargestMode(display);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class Api23Impl {
        private Api23Impl() {
        }

        static ModeCompat getMode(Context context, Display display) {
            Display.Mode currentMode = display.getMode();
            Point workaroundSize = DisplayCompat.getCurrentDisplaySizeFromWorkarounds(context, display);
            if (workaroundSize == null || physicalSizeEquals(currentMode, workaroundSize)) {
                return new ModeCompat(currentMode, true);
            }
            return new ModeCompat(currentMode, workaroundSize);
        }

        public static ModeCompat[] getSupportedModes(Context context, Display display) {
            ModeCompat modeCompat;
            Display.Mode[] supportedModes = display.getSupportedModes();
            ModeCompat[] supportedModesCompat = new ModeCompat[supportedModes.length];
            Display.Mode currentMode = display.getMode();
            Point workaroundSize = DisplayCompat.getCurrentDisplaySizeFromWorkarounds(context, display);
            if (workaroundSize == null || physicalSizeEquals(currentMode, workaroundSize)) {
                for (int i = 0; i < supportedModes.length; i++) {
                    boolean isNative = physicalSizeEquals(supportedModes[i], currentMode);
                    supportedModesCompat[i] = new ModeCompat(supportedModes[i], isNative);
                }
            } else {
                for (int i2 = 0; i2 < supportedModes.length; i2++) {
                    if (physicalSizeEquals(supportedModes[i2], currentMode)) {
                        modeCompat = new ModeCompat(supportedModes[i2], workaroundSize);
                    } else {
                        modeCompat = new ModeCompat(supportedModes[i2], false);
                    }
                    supportedModesCompat[i2] = modeCompat;
                }
            }
            return supportedModesCompat;
        }

        static boolean isCurrentModeTheLargestMode(Display display) {
            Display.Mode currentMode = display.getMode();
            Display.Mode[] supportedModes = display.getSupportedModes();
            for (Display.Mode supportedMode : supportedModes) {
                if (currentMode.getPhysicalHeight() < supportedMode.getPhysicalHeight() || currentMode.getPhysicalWidth() < supportedMode.getPhysicalWidth()) {
                    return false;
                }
            }
            return true;
        }

        static boolean physicalSizeEquals(Display.Mode mode, Point size) {
            return (mode.getPhysicalWidth() == size.x && mode.getPhysicalHeight() == size.y) || (mode.getPhysicalWidth() == size.y && mode.getPhysicalHeight() == size.x);
        }

        static boolean physicalSizeEquals(Display.Mode mode, Display.Mode otherMode) {
            return mode.getPhysicalWidth() == otherMode.getPhysicalWidth() && mode.getPhysicalHeight() == otherMode.getPhysicalHeight();
        }
    }

    /* loaded from: classes.dex */
    static class Api17Impl {
        private Api17Impl() {
        }

        static void getRealSize(Display display, Point displaySize) {
            display.getRealSize(displaySize);
        }
    }

    /* loaded from: classes.dex */
    public static final class ModeCompat {
        private final boolean mIsNative;
        private final Display.Mode mMode;
        private final Point mPhysicalSize;

        ModeCompat(Point physicalSize) {
            Preconditions.checkNotNull(physicalSize, "physicalSize == null");
            this.mPhysicalSize = physicalSize;
            this.mMode = null;
            this.mIsNative = true;
        }

        ModeCompat(Display.Mode mode, boolean isNative) {
            Preconditions.checkNotNull(mode, "mode == null, can't wrap a null reference");
            this.mPhysicalSize = new Point(Api23Impl.getPhysicalWidth(mode), Api23Impl.getPhysicalHeight(mode));
            this.mMode = mode;
            this.mIsNative = isNative;
        }

        ModeCompat(Display.Mode mode, Point physicalSize) {
            Preconditions.checkNotNull(mode, "mode == null, can't wrap a null reference");
            Preconditions.checkNotNull(physicalSize, "physicalSize == null");
            this.mPhysicalSize = physicalSize;
            this.mMode = mode;
            this.mIsNative = true;
        }

        public int getPhysicalWidth() {
            return this.mPhysicalSize.x;
        }

        public int getPhysicalHeight() {
            return this.mPhysicalSize.y;
        }

        @Deprecated
        public boolean isNative() {
            return this.mIsNative;
        }

        public Display.Mode toMode() {
            return this.mMode;
        }

        /* loaded from: classes.dex */
        static class Api23Impl {
            private Api23Impl() {
            }

            static int getPhysicalWidth(Display.Mode mode) {
                return mode.getPhysicalWidth();
            }

            static int getPhysicalHeight(Display.Mode mode) {
                return mode.getPhysicalHeight();
            }
        }
    }
}
