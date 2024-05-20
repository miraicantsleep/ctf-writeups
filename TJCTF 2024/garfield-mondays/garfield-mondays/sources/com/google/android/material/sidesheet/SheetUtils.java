package com.google.android.material.sidesheet;
/* loaded from: classes.dex */
final class SheetUtils {
    private SheetUtils() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isSwipeMostlyHorizontal(float xVelocity, float yVelocity) {
        return Math.abs(xVelocity) > Math.abs(yVelocity);
    }
}
