package com.android.volley;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicReference;
/* loaded from: classes.dex */
public abstract class AsyncNetwork implements Network {
    private ExecutorService mBlockingExecutor;
    private ExecutorService mNonBlockingExecutor;
    private ScheduledExecutorService mNonBlockingScheduledExecutor;

    /* loaded from: classes.dex */
    public interface OnRequestComplete {
        void onError(VolleyError volleyError);

        void onSuccess(NetworkResponse networkResponse);
    }

    public abstract void performRequest(Request<?> request, OnRequestComplete onRequestComplete);

    @Override // com.android.volley.Network
    public NetworkResponse performRequest(Request<?> request) throws VolleyError {
        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicReference<NetworkResponse> response = new AtomicReference<>();
        final AtomicReference<VolleyError> error = new AtomicReference<>();
        performRequest(request, new OnRequestComplete() { // from class: com.android.volley.AsyncNetwork.1
            @Override // com.android.volley.AsyncNetwork.OnRequestComplete
            public void onSuccess(NetworkResponse networkResponse) {
                response.set(networkResponse);
                latch.countDown();
            }

            @Override // com.android.volley.AsyncNetwork.OnRequestComplete
            public void onError(VolleyError volleyError) {
                error.set(volleyError);
                latch.countDown();
            }
        });
        try {
            latch.await();
            if (response.get() != null) {
                return response.get();
            }
            if (error.get() != null) {
                throw error.get();
            }
            throw new VolleyError("Neither response entry was set");
        } catch (InterruptedException e) {
            VolleyLog.e(e, "while waiting for CountDownLatch", new Object[0]);
            Thread.currentThread().interrupt();
            throw new VolleyError(e);
        }
    }

    public void setNonBlockingExecutor(ExecutorService executor) {
        this.mNonBlockingExecutor = executor;
    }

    public void setBlockingExecutor(ExecutorService executor) {
        this.mBlockingExecutor = executor;
    }

    public void setNonBlockingScheduledExecutor(ScheduledExecutorService executor) {
        this.mNonBlockingScheduledExecutor = executor;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public ExecutorService getBlockingExecutor() {
        return this.mBlockingExecutor;
    }

    protected ExecutorService getNonBlockingExecutor() {
        return this.mNonBlockingExecutor;
    }

    protected ScheduledExecutorService getNonBlockingScheduledExecutor() {
        return this.mNonBlockingScheduledExecutor;
    }
}
