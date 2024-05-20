package com.android.volley;

import android.os.Process;
import com.android.volley.Cache;
import java.util.concurrent.BlockingQueue;
/* loaded from: classes.dex */
public class CacheDispatcher extends Thread {
    private static final boolean DEBUG = VolleyLog.DEBUG;
    private final Cache mCache;
    private final BlockingQueue<Request<?>> mCacheQueue;
    private final ResponseDelivery mDelivery;
    private final BlockingQueue<Request<?>> mNetworkQueue;
    private volatile boolean mQuit = false;
    private final WaitingRequestManager mWaitingRequestManager;

    public CacheDispatcher(BlockingQueue<Request<?>> cacheQueue, BlockingQueue<Request<?>> networkQueue, Cache cache, ResponseDelivery delivery) {
        this.mCacheQueue = cacheQueue;
        this.mNetworkQueue = networkQueue;
        this.mCache = cache;
        this.mDelivery = delivery;
        this.mWaitingRequestManager = new WaitingRequestManager(this, networkQueue, delivery);
    }

    public void quit() {
        this.mQuit = true;
        interrupt();
    }

    @Override // java.lang.Thread, java.lang.Runnable
    public void run() {
        if (DEBUG) {
            VolleyLog.v("start new dispatcher", new Object[0]);
        }
        Process.setThreadPriority(10);
        this.mCache.initialize();
        while (true) {
            try {
                processRequest();
            } catch (InterruptedException e) {
                if (this.mQuit) {
                    Thread.currentThread().interrupt();
                    return;
                }
                VolleyLog.e("Ignoring spurious interrupt of CacheDispatcher thread; use quit() to terminate it", new Object[0]);
            }
        }
    }

    private void processRequest() throws InterruptedException {
        Request<?> request = this.mCacheQueue.take();
        processRequest(request);
    }

    void processRequest(final Request<?> request) throws InterruptedException {
        request.addMarker("cache-queue-take");
        request.sendEvent(1);
        try {
            if (request.isCanceled()) {
                request.finish("cache-discard-canceled");
                return;
            }
            Cache.Entry entry = this.mCache.get(request.getCacheKey());
            if (entry == null) {
                request.addMarker("cache-miss");
                if (!this.mWaitingRequestManager.maybeAddToWaitingRequests(request)) {
                    this.mNetworkQueue.put(request);
                }
                return;
            }
            long currentTimeMillis = System.currentTimeMillis();
            if (entry.isExpired(currentTimeMillis)) {
                request.addMarker("cache-hit-expired");
                request.setCacheEntry(entry);
                if (!this.mWaitingRequestManager.maybeAddToWaitingRequests(request)) {
                    this.mNetworkQueue.put(request);
                }
                return;
            }
            request.addMarker("cache-hit");
            Response<?> response = request.parseNetworkResponse(new NetworkResponse(entry.data, entry.responseHeaders));
            request.addMarker("cache-hit-parsed");
            if (!response.isSuccess()) {
                request.addMarker("cache-parsing-failed");
                this.mCache.invalidate(request.getCacheKey(), true);
                request.setCacheEntry(null);
                if (!this.mWaitingRequestManager.maybeAddToWaitingRequests(request)) {
                    this.mNetworkQueue.put(request);
                }
                return;
            }
            if (entry.refreshNeeded(currentTimeMillis)) {
                request.addMarker("cache-hit-refresh-needed");
                request.setCacheEntry(entry);
                response.intermediate = true;
                if (this.mWaitingRequestManager.maybeAddToWaitingRequests(request)) {
                    this.mDelivery.postResponse(request, response);
                } else {
                    this.mDelivery.postResponse(request, response, new Runnable() { // from class: com.android.volley.CacheDispatcher.1
                        @Override // java.lang.Runnable
                        public void run() {
                            try {
                                CacheDispatcher.this.mNetworkQueue.put(request);
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                            }
                        }
                    });
                }
            } else {
                this.mDelivery.postResponse(request, response);
            }
        } finally {
            request.sendEvent(2);
        }
    }
}
