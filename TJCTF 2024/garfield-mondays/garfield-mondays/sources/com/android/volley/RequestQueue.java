package com.android.volley;

import android.os.Handler;
import android.os.Looper;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;
/* loaded from: classes.dex */
public class RequestQueue {
    private static final int DEFAULT_NETWORK_THREAD_POOL_SIZE = 4;
    private final Cache mCache;
    private CacheDispatcher mCacheDispatcher;
    private final PriorityBlockingQueue<Request<?>> mCacheQueue;
    private final Set<Request<?>> mCurrentRequests;
    private final ResponseDelivery mDelivery;
    private final NetworkDispatcher[] mDispatchers;
    private final List<RequestEventListener> mEventListeners;
    private final List<RequestFinishedListener> mFinishedListeners;
    private final Network mNetwork;
    private final PriorityBlockingQueue<Request<?>> mNetworkQueue;
    private final AtomicInteger mSequenceGenerator;

    @Retention(RetentionPolicy.SOURCE)
    /* loaded from: classes.dex */
    public @interface RequestEvent {
        public static final int REQUEST_CACHE_LOOKUP_FINISHED = 2;
        public static final int REQUEST_CACHE_LOOKUP_STARTED = 1;
        public static final int REQUEST_FINISHED = 5;
        public static final int REQUEST_NETWORK_DISPATCH_FINISHED = 4;
        public static final int REQUEST_NETWORK_DISPATCH_STARTED = 3;
        public static final int REQUEST_QUEUED = 0;
    }

    /* loaded from: classes.dex */
    public interface RequestEventListener {
        void onRequestEvent(Request<?> request, int i);
    }

    /* loaded from: classes.dex */
    public interface RequestFilter {
        boolean apply(Request<?> request);
    }

    @Deprecated
    /* loaded from: classes.dex */
    public interface RequestFinishedListener<T> {
        void onRequestFinished(Request<T> request);
    }

    public RequestQueue(Cache cache, Network network, int threadPoolSize, ResponseDelivery delivery) {
        this.mSequenceGenerator = new AtomicInteger();
        this.mCurrentRequests = new HashSet();
        this.mCacheQueue = new PriorityBlockingQueue<>();
        this.mNetworkQueue = new PriorityBlockingQueue<>();
        this.mFinishedListeners = new ArrayList();
        this.mEventListeners = new ArrayList();
        this.mCache = cache;
        this.mNetwork = network;
        this.mDispatchers = new NetworkDispatcher[threadPoolSize];
        this.mDelivery = delivery;
    }

    public RequestQueue(Cache cache, Network network, int threadPoolSize) {
        this(cache, network, threadPoolSize, new ExecutorDelivery(new Handler(Looper.getMainLooper())));
    }

    public RequestQueue(Cache cache, Network network) {
        this(cache, network, 4);
    }

    public void start() {
        stop();
        this.mCacheDispatcher = new CacheDispatcher(this.mCacheQueue, this.mNetworkQueue, this.mCache, this.mDelivery);
        this.mCacheDispatcher.start();
        for (int i = 0; i < this.mDispatchers.length; i++) {
            NetworkDispatcher networkDispatcher = new NetworkDispatcher(this.mNetworkQueue, this.mNetwork, this.mCache, this.mDelivery);
            this.mDispatchers[i] = networkDispatcher;
            networkDispatcher.start();
        }
    }

    public void stop() {
        NetworkDispatcher[] networkDispatcherArr;
        if (this.mCacheDispatcher != null) {
            this.mCacheDispatcher.quit();
        }
        for (NetworkDispatcher mDispatcher : this.mDispatchers) {
            if (mDispatcher != null) {
                mDispatcher.quit();
            }
        }
    }

    public int getSequenceNumber() {
        return this.mSequenceGenerator.incrementAndGet();
    }

    public Cache getCache() {
        return this.mCache;
    }

    public void cancelAll(RequestFilter filter) {
        synchronized (this.mCurrentRequests) {
            for (Request<?> request : this.mCurrentRequests) {
                if (filter.apply(request)) {
                    request.cancel();
                }
            }
        }
    }

    public void cancelAll(final Object tag) {
        if (tag == null) {
            throw new IllegalArgumentException("Cannot cancelAll with a null tag");
        }
        cancelAll(new RequestFilter() { // from class: com.android.volley.RequestQueue.1
            @Override // com.android.volley.RequestQueue.RequestFilter
            public boolean apply(Request<?> request) {
                return request.getTag() == tag;
            }
        });
    }

    public <T> Request<T> add(Request<T> request) {
        request.setRequestQueue(this);
        synchronized (this.mCurrentRequests) {
            this.mCurrentRequests.add(request);
        }
        request.setSequence(getSequenceNumber());
        request.addMarker("add-to-queue");
        sendRequestEvent(request, 0);
        beginRequest(request);
        return request;
    }

    <T> void beginRequest(Request<T> request) {
        if (!request.shouldCache()) {
            sendRequestOverNetwork(request);
        } else {
            this.mCacheQueue.add(request);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public <T> void finish(Request<T> request) {
        synchronized (this.mCurrentRequests) {
            this.mCurrentRequests.remove(request);
        }
        synchronized (this.mFinishedListeners) {
            for (RequestFinishedListener<T> listener : this.mFinishedListeners) {
                listener.onRequestFinished(request);
            }
        }
        sendRequestEvent(request, 5);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void sendRequestEvent(Request<?> request, int event) {
        synchronized (this.mEventListeners) {
            for (RequestEventListener listener : this.mEventListeners) {
                listener.onRequestEvent(request, event);
            }
        }
    }

    public void addRequestEventListener(RequestEventListener listener) {
        synchronized (this.mEventListeners) {
            this.mEventListeners.add(listener);
        }
    }

    public void removeRequestEventListener(RequestEventListener listener) {
        synchronized (this.mEventListeners) {
            this.mEventListeners.remove(listener);
        }
    }

    @Deprecated
    public <T> void addRequestFinishedListener(RequestFinishedListener<T> listener) {
        synchronized (this.mFinishedListeners) {
            this.mFinishedListeners.add(listener);
        }
    }

    @Deprecated
    public <T> void removeRequestFinishedListener(RequestFinishedListener<T> listener) {
        synchronized (this.mFinishedListeners) {
            this.mFinishedListeners.remove(listener);
        }
    }

    public ResponseDelivery getResponseDelivery() {
        return this.mDelivery;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public <T> void sendRequestOverNetwork(Request<T> request) {
        this.mNetworkQueue.add(request);
    }
}
