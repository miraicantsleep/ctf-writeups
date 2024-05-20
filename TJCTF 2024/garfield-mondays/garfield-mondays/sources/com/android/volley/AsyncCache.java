package com.android.volley;

import com.android.volley.Cache;
/* loaded from: classes.dex */
public abstract class AsyncCache {

    /* loaded from: classes.dex */
    public interface OnGetCompleteCallback {
        void onGetComplete(Cache.Entry entry);
    }

    /* loaded from: classes.dex */
    public interface OnWriteCompleteCallback {
        void onWriteComplete();
    }

    public abstract void clear(OnWriteCompleteCallback onWriteCompleteCallback);

    public abstract void get(String str, OnGetCompleteCallback onGetCompleteCallback);

    public abstract void initialize(OnWriteCompleteCallback onWriteCompleteCallback);

    public abstract void invalidate(String str, boolean z, OnWriteCompleteCallback onWriteCompleteCallback);

    public abstract void put(String str, Cache.Entry entry, OnWriteCompleteCallback onWriteCompleteCallback);

    public abstract void remove(String str, OnWriteCompleteCallback onWriteCompleteCallback);
}
