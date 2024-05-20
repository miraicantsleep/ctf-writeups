package com.android.volley;

import com.android.volley.Cache;
/* loaded from: classes.dex */
public class Response<T> {
    public final Cache.Entry cacheEntry;
    public final VolleyError error;
    public boolean intermediate;
    public final T result;

    /* loaded from: classes.dex */
    public interface ErrorListener {
        void onErrorResponse(VolleyError volleyError);
    }

    /* loaded from: classes.dex */
    public interface Listener<T> {
        void onResponse(T t);
    }

    public static <T> Response<T> success(T result, Cache.Entry cacheEntry) {
        return new Response<>(result, cacheEntry);
    }

    public static <T> Response<T> error(VolleyError error) {
        return new Response<>(error);
    }

    public boolean isSuccess() {
        return this.error == null;
    }

    private Response(T result, Cache.Entry cacheEntry) {
        this.intermediate = false;
        this.result = result;
        this.cacheEntry = cacheEntry;
        this.error = null;
    }

    private Response(VolleyError error) {
        this.intermediate = false;
        this.result = null;
        this.cacheEntry = null;
        this.error = error;
    }
}
