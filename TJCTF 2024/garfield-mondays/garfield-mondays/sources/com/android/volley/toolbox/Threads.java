package com.android.volley.toolbox;

import android.os.Looper;
/* loaded from: classes.dex */
final class Threads {
    private Threads() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void throwIfNotOnMainThread() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            throw new IllegalStateException("Must be invoked from the main thread.");
        }
    }
}
