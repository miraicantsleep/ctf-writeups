package androidx.core.graphics;

import android.graphics.BlendMode;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.graphics.Rect;
import android.os.Build;
import androidx.core.graphics.BlendModeUtils;
import androidx.core.util.Pair;
/* loaded from: classes.dex */
public final class PaintCompat {
    private static final String EM_STRING = "m";
    private static final String TOFU_STRING = "\udfffd";
    private static final ThreadLocal<Pair<Rect, Rect>> sRectThreadLocal = new ThreadLocal<>();

    public static boolean hasGlyph(Paint paint, String string) {
        return Api23Impl.hasGlyph(paint, string);
    }

    public static boolean setBlendMode(Paint paint, BlendModeCompat blendMode) {
        if (Build.VERSION.SDK_INT >= 29) {
            Object blendModePlatform = blendMode != null ? BlendModeUtils.Api29Impl.obtainBlendModeFromCompat(blendMode) : null;
            Api29Impl.setBlendMode(paint, blendModePlatform);
            return true;
        } else if (blendMode != null) {
            PorterDuff.Mode mode = BlendModeUtils.obtainPorterDuffFromCompat(blendMode);
            paint.setXfermode(mode != null ? new PorterDuffXfermode(mode) : null);
            return mode != null;
        } else {
            paint.setXfermode(null);
            return true;
        }
    }

    private static Pair<Rect, Rect> obtainEmptyRects() {
        Pair<Rect, Rect> rects = sRectThreadLocal.get();
        if (rects == null) {
            Pair<Rect, Rect> rects2 = new Pair<>(new Rect(), new Rect());
            sRectThreadLocal.set(rects2);
            return rects2;
        }
        rects.first.setEmpty();
        rects.second.setEmpty();
        return rects;
    }

    private PaintCompat() {
    }

    /* loaded from: classes.dex */
    static class Api29Impl {
        private Api29Impl() {
        }

        static void setBlendMode(Paint paint, Object blendmode) {
            paint.setBlendMode((BlendMode) blendmode);
        }
    }

    /* loaded from: classes.dex */
    static class Api23Impl {
        private Api23Impl() {
        }

        static boolean hasGlyph(Paint paint, String string) {
            return paint.hasGlyph(string);
        }
    }
}
