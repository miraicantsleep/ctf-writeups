package com.android.volley;

import com.android.volley.Request;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class WaitingRequestManager implements Request.NetworkRequestCompleteListener {
    private final CacheDispatcher mCacheDispatcher;
    private final BlockingQueue<Request<?>> mNetworkQueue;
    private final RequestQueue mRequestQueue;
    private final ResponseDelivery mResponseDelivery;
    private final Map<String, List<Request<?>>> mWaitingRequests;

    /* JADX INFO: Access modifiers changed from: package-private */
    public WaitingRequestManager(RequestQueue requestQueue) {
        this.mWaitingRequests = new HashMap();
        this.mRequestQueue = requestQueue;
        this.mResponseDelivery = this.mRequestQueue.getResponseDelivery();
        this.mCacheDispatcher = null;
        this.mNetworkQueue = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public WaitingRequestManager(CacheDispatcher cacheDispatcher, BlockingQueue<Request<?>> networkQueue, ResponseDelivery responseDelivery) {
        this.mWaitingRequests = new HashMap();
        this.mRequestQueue = null;
        this.mResponseDelivery = responseDelivery;
        this.mCacheDispatcher = cacheDispatcher;
        this.mNetworkQueue = networkQueue;
    }

    @Override // com.android.volley.Request.NetworkRequestCompleteListener
    public void onResponseReceived(Request<?> request, Response<?> response) {
        List<Request<?>> waitingRequests;
        if (response.cacheEntry == null || response.cacheEntry.isExpired()) {
            onNoUsableResponseReceived(request);
            return;
        }
        String cacheKey = request.getCacheKey();
        synchronized (this) {
            waitingRequests = this.mWaitingRequests.remove(cacheKey);
        }
        if (waitingRequests != null) {
            if (VolleyLog.DEBUG) {
                VolleyLog.v("Releasing %d waiting requests for cacheKey=%s.", Integer.valueOf(waitingRequests.size()), cacheKey);
            }
            for (Request<?> waiting : waitingRequests) {
                this.mResponseDelivery.postResponse(waiting, response);
            }
        }
    }

    @Override // com.android.volley.Request.NetworkRequestCompleteListener
    public synchronized void onNoUsableResponseReceived(Request<?> request) {
        String cacheKey = request.getCacheKey();
        List<Request<?>> waitingRequests = this.mWaitingRequests.remove(cacheKey);
        if (waitingRequests != null && !waitingRequests.isEmpty()) {
            if (VolleyLog.DEBUG) {
                VolleyLog.v("%d waiting requests for cacheKey=%s; resend to network", Integer.valueOf(waitingRequests.size()), cacheKey);
            }
            Request<?> nextInLine = waitingRequests.remove(0);
            this.mWaitingRequests.put(cacheKey, waitingRequests);
            nextInLine.setNetworkRequestCompleteListener(this);
            if (this.mRequestQueue != null) {
                this.mRequestQueue.sendRequestOverNetwork(nextInLine);
            } else if (this.mCacheDispatcher != null && this.mNetworkQueue != null) {
                try {
                    this.mNetworkQueue.put(nextInLine);
                } catch (InterruptedException iex) {
                    VolleyLog.e("Couldn't add request to queue. %s", iex.toString());
                    Thread.currentThread().interrupt();
                    this.mCacheDispatcher.quit();
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized boolean maybeAddToWaitingRequests(Request<?> request) {
        String cacheKey = request.getCacheKey();
        if (this.mWaitingRequests.containsKey(cacheKey)) {
            List<Request<?>> stagedRequests = this.mWaitingRequests.get(cacheKey);
            if (stagedRequests == null) {
                stagedRequests = new ArrayList();
            }
            request.addMarker("waiting-for-response");
            stagedRequests.add(request);
            this.mWaitingRequests.put(cacheKey, stagedRequests);
            if (VolleyLog.DEBUG) {
                VolleyLog.d("Request for cacheKey=%s is in flight, putting on hold.", cacheKey);
            }
            return true;
        }
        this.mWaitingRequests.put(cacheKey, null);
        request.setNetworkRequestCompleteListener(this);
        if (VolleyLog.DEBUG) {
            VolleyLog.d("new request, sending to network %s", cacheKey);
        }
        return false;
    }
}
