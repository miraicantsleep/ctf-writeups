package com.android.volley.toolbox;

import com.android.volley.AsyncCache;
import com.android.volley.Cache;
/* loaded from: classes.dex */
public class NoAsyncCache extends AsyncCache {
    @Override // com.android.volley.AsyncCache
    public void get(String key, AsyncCache.OnGetCompleteCallback callback) {
        callback.onGetComplete(null);
    }

    @Override // com.android.volley.AsyncCache
    public void put(String key, Cache.Entry entry, AsyncCache.OnWriteCompleteCallback callback) {
        callback.onWriteComplete();
    }

    @Override // com.android.volley.AsyncCache
    public void clear(AsyncCache.OnWriteCompleteCallback callback) {
        callback.onWriteComplete();
    }

    @Override // com.android.volley.AsyncCache
    public void initialize(AsyncCache.OnWriteCompleteCallback callback) {
        callback.onWriteComplete();
    }

    @Override // com.android.volley.AsyncCache
    public void invalidate(String key, boolean fullExpire, AsyncCache.OnWriteCompleteCallback callback) {
        callback.onWriteComplete();
    }

    @Override // com.android.volley.AsyncCache
    public void remove(String key, AsyncCache.OnWriteCompleteCallback callback) {
        callback.onWriteComplete();
    }
}
