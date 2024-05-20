package com.android.volley.toolbox;

import android.os.Handler;
import android.os.Looper;
import com.android.volley.Cache;
import com.android.volley.NetworkResponse;
import com.android.volley.Request;
import com.android.volley.Response;
/* loaded from: classes.dex */
public class ClearCacheRequest extends Request<Object> {
    private final Cache mCache;
    private final Runnable mCallback;

    public ClearCacheRequest(Cache cache, Runnable callback) {
        super(0, null, null);
        this.mCache = cache;
        this.mCallback = callback;
    }

    @Override // com.android.volley.Request
    public boolean isCanceled() {
        this.mCache.clear();
        if (this.mCallback != null) {
            Handler handler = new Handler(Looper.getMainLooper());
            handler.postAtFrontOfQueue(this.mCallback);
            return true;
        }
        return true;
    }

    @Override // com.android.volley.Request
    public Request.Priority getPriority() {
        return Request.Priority.IMMEDIATE;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.android.volley.Request
    public Response<Object> parseNetworkResponse(NetworkResponse response) {
        return null;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.android.volley.Request
    public void deliverResponse(Object response) {
    }
}
