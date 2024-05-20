package com.android.volley;
/* loaded from: classes.dex */
public abstract class RequestTask<T> implements Runnable {
    final Request<T> mRequest;

    public RequestTask(Request<T> request) {
        this.mRequest = request;
    }

    public int compareTo(RequestTask<?> other) {
        return this.mRequest.compareTo((Request) other.mRequest);
    }
}
