package androidx.core.view.animation;

import android.graphics.Path;
import android.view.animation.Interpolator;
import android.view.animation.PathInterpolator;
/* loaded from: classes.dex */
public final class PathInterpolatorCompat {
    private PathInterpolatorCompat() {
    }

    public static Interpolator create(Path path) {
        return Api21Impl.createPathInterpolator(path);
    }

    public static Interpolator create(float controlX, float controlY) {
        return Api21Impl.createPathInterpolator(controlX, controlY);
    }

    public static Interpolator create(float controlX1, float controlY1, float controlX2, float controlY2) {
        return Api21Impl.createPathInterpolator(controlX1, controlY1, controlX2, controlY2);
    }

    /* loaded from: classes.dex */
    static class Api21Impl {
        private Api21Impl() {
        }

        static PathInterpolator createPathInterpolator(Path path) {
            return new PathInterpolator(path);
        }

        static PathInterpolator createPathInterpolator(float controlX, float controlY) {
            return new PathInterpolator(controlX, controlY);
        }

        static PathInterpolator createPathInterpolator(float controlX1, float controlY1, float controlX2, float controlY2) {
            return new PathInterpolator(controlX1, controlY1, controlX2, controlY2);
        }
    }
}
