package com.android.volley;

import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import androidx.recyclerview.widget.ItemTouchHelper;
import com.android.volley.AsyncCache;
import com.android.volley.AsyncNetwork;
import com.android.volley.Cache;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
/* loaded from: classes.dex */
public class AsyncRequestQueue extends RequestQueue {
    private static final int DEFAULT_BLOCKING_THREAD_POOL_SIZE = 4;
    private final AsyncCache mAsyncCache;
    private ExecutorService mBlockingExecutor;
    private final Object mCacheInitializationLock;
    private ExecutorFactory mExecutorFactory;
    private volatile boolean mIsCacheInitialized;
    private final AsyncNetwork mNetwork;
    private ExecutorService mNonBlockingExecutor;
    private ScheduledExecutorService mNonBlockingScheduledExecutor;
    private final List<Request<?>> mRequestsAwaitingCacheInitialization;
    private final WaitingRequestManager mWaitingRequestManager;

    /* loaded from: classes.dex */
    public static abstract class ExecutorFactory {
        public abstract ExecutorService createBlockingExecutor(BlockingQueue<Runnable> blockingQueue);

        public abstract ExecutorService createNonBlockingExecutor(BlockingQueue<Runnable> blockingQueue);

        public abstract ScheduledExecutorService createNonBlockingScheduledExecutor();
    }

    private AsyncRequestQueue(Cache cache, AsyncNetwork network, AsyncCache asyncCache, ResponseDelivery responseDelivery, ExecutorFactory executorFactory) {
        super(cache, network, 0, responseDelivery);
        this.mWaitingRequestManager = new WaitingRequestManager(this);
        this.mRequestsAwaitingCacheInitialization = new ArrayList();
        this.mIsCacheInitialized = false;
        this.mCacheInitializationLock = new Object[0];
        this.mAsyncCache = asyncCache;
        this.mNetwork = network;
        this.mExecutorFactory = executorFactory;
    }

    @Override // com.android.volley.RequestQueue
    public void start() {
        stop();
        this.mNonBlockingExecutor = this.mExecutorFactory.createNonBlockingExecutor(getBlockingQueue());
        this.mBlockingExecutor = this.mExecutorFactory.createBlockingExecutor(getBlockingQueue());
        this.mNonBlockingScheduledExecutor = this.mExecutorFactory.createNonBlockingScheduledExecutor();
        this.mNetwork.setBlockingExecutor(this.mBlockingExecutor);
        this.mNetwork.setNonBlockingExecutor(this.mNonBlockingExecutor);
        this.mNetwork.setNonBlockingScheduledExecutor(this.mNonBlockingScheduledExecutor);
        if (this.mAsyncCache != null) {
            this.mNonBlockingExecutor.execute(new Runnable() { // from class: com.android.volley.AsyncRequestQueue.1
                @Override // java.lang.Runnable
                public void run() {
                    AsyncRequestQueue.this.mAsyncCache.initialize(new AsyncCache.OnWriteCompleteCallback() { // from class: com.android.volley.AsyncRequestQueue.1.1
                        @Override // com.android.volley.AsyncCache.OnWriteCompleteCallback
                        public void onWriteComplete() {
                            AsyncRequestQueue.this.onCacheInitializationComplete();
                        }
                    });
                }
            });
        } else {
            this.mBlockingExecutor.execute(new Runnable() { // from class: com.android.volley.AsyncRequestQueue.2
                @Override // java.lang.Runnable
                public void run() {
                    AsyncRequestQueue.this.getCache().initialize();
                    AsyncRequestQueue.this.mNonBlockingExecutor.execute(new Runnable() { // from class: com.android.volley.AsyncRequestQueue.2.1
                        @Override // java.lang.Runnable
                        public void run() {
                            AsyncRequestQueue.this.onCacheInitializationComplete();
                        }
                    });
                }
            });
        }
    }

    @Override // com.android.volley.RequestQueue
    public void stop() {
        if (this.mNonBlockingExecutor != null) {
            this.mNonBlockingExecutor.shutdownNow();
            this.mNonBlockingExecutor = null;
        }
        if (this.mBlockingExecutor != null) {
            this.mBlockingExecutor.shutdownNow();
            this.mBlockingExecutor = null;
        }
        if (this.mNonBlockingScheduledExecutor != null) {
            this.mNonBlockingScheduledExecutor.shutdownNow();
            this.mNonBlockingScheduledExecutor = null;
        }
    }

    @Override // com.android.volley.RequestQueue
    <T> void beginRequest(Request<T> request) {
        if (!this.mIsCacheInitialized) {
            synchronized (this.mCacheInitializationLock) {
                if (!this.mIsCacheInitialized) {
                    this.mRequestsAwaitingCacheInitialization.add(request);
                    return;
                }
            }
        }
        if (request.shouldCache()) {
            if (this.mAsyncCache != null) {
                this.mNonBlockingExecutor.execute(new CacheTask(request));
                return;
            } else {
                this.mBlockingExecutor.execute(new CacheTask(request));
                return;
            }
        }
        sendRequestOverNetwork(request);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onCacheInitializationComplete() {
        List<Request<?>> requestsToDispatch;
        synchronized (this.mCacheInitializationLock) {
            requestsToDispatch = new ArrayList<>(this.mRequestsAwaitingCacheInitialization);
            this.mRequestsAwaitingCacheInitialization.clear();
            this.mIsCacheInitialized = true;
        }
        for (Request<?> request : requestsToDispatch) {
            beginRequest(request);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.android.volley.RequestQueue
    public <T> void sendRequestOverNetwork(Request<T> request) {
        this.mNonBlockingExecutor.execute(new NetworkTask(request));
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class CacheTask<T> extends RequestTask<T> {
        CacheTask(Request<T> request) {
            super(request);
        }

        @Override // java.lang.Runnable
        public void run() {
            if (this.mRequest.isCanceled()) {
                this.mRequest.finish("cache-discard-canceled");
                return;
            }
            this.mRequest.addMarker("cache-queue-take");
            if (AsyncRequestQueue.this.mAsyncCache != null) {
                AsyncRequestQueue.this.mAsyncCache.get(this.mRequest.getCacheKey(), new AsyncCache.OnGetCompleteCallback() { // from class: com.android.volley.AsyncRequestQueue.CacheTask.1
                    @Override // com.android.volley.AsyncCache.OnGetCompleteCallback
                    public void onGetComplete(Cache.Entry entry) {
                        AsyncRequestQueue.this.handleEntry(entry, CacheTask.this.mRequest);
                    }
                });
                return;
            }
            Cache.Entry entry = AsyncRequestQueue.this.getCache().get(this.mRequest.getCacheKey());
            AsyncRequestQueue.this.handleEntry(entry, this.mRequest);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void handleEntry(Cache.Entry entry, Request<?> mRequest) {
        if (entry == null) {
            mRequest.addMarker("cache-miss");
            if (!this.mWaitingRequestManager.maybeAddToWaitingRequests(mRequest)) {
                sendRequestOverNetwork(mRequest);
                return;
            }
            return;
        }
        long currentTimeMillis = System.currentTimeMillis();
        if (entry.isExpired(currentTimeMillis)) {
            mRequest.addMarker("cache-hit-expired");
            mRequest.setCacheEntry(entry);
            if (!this.mWaitingRequestManager.maybeAddToWaitingRequests(mRequest)) {
                sendRequestOverNetwork(mRequest);
                return;
            }
            return;
        }
        this.mBlockingExecutor.execute(new CacheParseTask(mRequest, entry, currentTimeMillis));
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class CacheParseTask<T> extends RequestTask<T> {
        Cache.Entry entry;
        long startTimeMillis;

        CacheParseTask(Request<T> request, Cache.Entry entry, long startTimeMillis) {
            super(request);
            this.entry = entry;
            this.startTimeMillis = startTimeMillis;
        }

        @Override // java.lang.Runnable
        public void run() {
            this.mRequest.addMarker("cache-hit");
            Response<T> parseNetworkResponse = this.mRequest.parseNetworkResponse(new NetworkResponse((int) ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, this.entry.data, false, 0L, this.entry.allResponseHeaders));
            this.mRequest.addMarker("cache-hit-parsed");
            if (!this.entry.refreshNeeded(this.startTimeMillis)) {
                AsyncRequestQueue.this.getResponseDelivery().postResponse(this.mRequest, parseNetworkResponse);
                return;
            }
            this.mRequest.addMarker("cache-hit-refresh-needed");
            this.mRequest.setCacheEntry(this.entry);
            parseNetworkResponse.intermediate = true;
            if (!AsyncRequestQueue.this.mWaitingRequestManager.maybeAddToWaitingRequests(this.mRequest)) {
                AsyncRequestQueue.this.getResponseDelivery().postResponse(this.mRequest, parseNetworkResponse, new Runnable() { // from class: com.android.volley.AsyncRequestQueue.CacheParseTask.1
                    @Override // java.lang.Runnable
                    public void run() {
                        AsyncRequestQueue.this.sendRequestOverNetwork(CacheParseTask.this.mRequest);
                    }
                });
            } else {
                AsyncRequestQueue.this.getResponseDelivery().postResponse(this.mRequest, parseNetworkResponse);
            }
        }
    }

    /* loaded from: classes.dex */
    private class ParseErrorTask<T> extends RequestTask<T> {
        VolleyError volleyError;

        ParseErrorTask(Request<T> request, VolleyError volleyError) {
            super(request);
            this.volleyError = volleyError;
        }

        @Override // java.lang.Runnable
        public void run() {
            VolleyError parsedError = this.mRequest.parseNetworkError(this.volleyError);
            AsyncRequestQueue.this.getResponseDelivery().postError(this.mRequest, parsedError);
            this.mRequest.notifyListenerResponseNotUsable();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class NetworkTask<T> extends RequestTask<T> {
        NetworkTask(Request<T> request) {
            super(request);
        }

        @Override // java.lang.Runnable
        public void run() {
            if (this.mRequest.isCanceled()) {
                this.mRequest.finish("network-discard-cancelled");
                this.mRequest.notifyListenerResponseNotUsable();
                return;
            }
            final long startTimeMs = SystemClock.elapsedRealtime();
            this.mRequest.addMarker("network-queue-take");
            AsyncRequestQueue.this.mNetwork.performRequest(this.mRequest, new AsyncNetwork.OnRequestComplete() { // from class: com.android.volley.AsyncRequestQueue.NetworkTask.1
                @Override // com.android.volley.AsyncNetwork.OnRequestComplete
                public void onSuccess(NetworkResponse networkResponse) {
                    NetworkTask.this.mRequest.addMarker("network-http-complete");
                    if (!networkResponse.notModified || !NetworkTask.this.mRequest.hasHadResponseDelivered()) {
                        AsyncRequestQueue.this.mBlockingExecutor.execute(new NetworkParseTask(NetworkTask.this.mRequest, networkResponse));
                        return;
                    }
                    NetworkTask.this.mRequest.finish("not-modified");
                    NetworkTask.this.mRequest.notifyListenerResponseNotUsable();
                }

                @Override // com.android.volley.AsyncNetwork.OnRequestComplete
                public void onError(VolleyError volleyError) {
                    volleyError.setNetworkTimeMs(SystemClock.elapsedRealtime() - startTimeMs);
                    AsyncRequestQueue.this.mBlockingExecutor.execute(new ParseErrorTask(NetworkTask.this.mRequest, volleyError));
                }
            });
        }
    }

    /* loaded from: classes.dex */
    private class NetworkParseTask<T> extends RequestTask<T> {
        NetworkResponse networkResponse;

        NetworkParseTask(Request<T> request, NetworkResponse networkResponse) {
            super(request);
            this.networkResponse = networkResponse;
        }

        @Override // java.lang.Runnable
        public void run() {
            Response<T> parseNetworkResponse = this.mRequest.parseNetworkResponse(this.networkResponse);
            this.mRequest.addMarker("network-parse-complete");
            if (!this.mRequest.shouldCache() || parseNetworkResponse.cacheEntry == null) {
                AsyncRequestQueue.this.finishRequest(this.mRequest, parseNetworkResponse, false);
            } else if (AsyncRequestQueue.this.mAsyncCache != null) {
                AsyncRequestQueue.this.mNonBlockingExecutor.execute(new CachePutTask(this.mRequest, parseNetworkResponse));
            } else {
                AsyncRequestQueue.this.mBlockingExecutor.execute(new CachePutTask(this.mRequest, parseNetworkResponse));
            }
        }
    }

    /* loaded from: classes.dex */
    private class CachePutTask<T> extends RequestTask<T> {
        Response<?> response;

        CachePutTask(Request<T> request, Response<?> response) {
            super(request);
            this.response = response;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (AsyncRequestQueue.this.mAsyncCache != null) {
                AsyncRequestQueue.this.mAsyncCache.put(this.mRequest.getCacheKey(), this.response.cacheEntry, new AsyncCache.OnWriteCompleteCallback() { // from class: com.android.volley.AsyncRequestQueue.CachePutTask.1
                    @Override // com.android.volley.AsyncCache.OnWriteCompleteCallback
                    public void onWriteComplete() {
                        AsyncRequestQueue.this.finishRequest(CachePutTask.this.mRequest, CachePutTask.this.response, true);
                    }
                });
                return;
            }
            AsyncRequestQueue.this.getCache().put(this.mRequest.getCacheKey(), this.response.cacheEntry);
            AsyncRequestQueue.this.finishRequest(this.mRequest, this.response, true);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void finishRequest(Request<?> mRequest, Response<?> response, boolean cached) {
        if (cached) {
            mRequest.addMarker("network-cache-written");
        }
        mRequest.markDelivered();
        getResponseDelivery().postResponse(mRequest, response);
        mRequest.notifyListenerResponseReceived(response);
    }

    private static PriorityBlockingQueue<Runnable> getBlockingQueue() {
        return new PriorityBlockingQueue<>(11, new Comparator<Runnable>() { // from class: com.android.volley.AsyncRequestQueue.3
            @Override // java.util.Comparator
            public int compare(Runnable r1, Runnable r2) {
                if (!(r1 instanceof RequestTask)) {
                    return r2 instanceof RequestTask ? -1 : 0;
                } else if (r2 instanceof RequestTask) {
                    return ((RequestTask) r1).compareTo((RequestTask) r2);
                } else {
                    return 1;
                }
            }
        });
    }

    /* loaded from: classes.dex */
    public static class Builder {
        private final AsyncNetwork mNetwork;
        private AsyncCache mAsyncCache = null;
        private Cache mCache = null;
        private ExecutorFactory mExecutorFactory = null;
        private ResponseDelivery mResponseDelivery = null;

        public Builder(AsyncNetwork asyncNetwork) {
            if (asyncNetwork == null) {
                throw new IllegalArgumentException("Network cannot be null");
            }
            this.mNetwork = asyncNetwork;
        }

        public Builder setExecutorFactory(ExecutorFactory executorFactory) {
            this.mExecutorFactory = executorFactory;
            return this;
        }

        public Builder setResponseDelivery(ResponseDelivery responseDelivery) {
            this.mResponseDelivery = responseDelivery;
            return this;
        }

        public Builder setAsyncCache(AsyncCache asyncCache) {
            this.mAsyncCache = asyncCache;
            return this;
        }

        public Builder setCache(Cache cache) {
            this.mCache = cache;
            return this;
        }

        private ExecutorFactory getDefaultExecutorFactory() {
            return new ExecutorFactory() { // from class: com.android.volley.AsyncRequestQueue.Builder.1
                @Override // com.android.volley.AsyncRequestQueue.ExecutorFactory
                public ExecutorService createNonBlockingExecutor(BlockingQueue<Runnable> taskQueue) {
                    return getNewThreadPoolExecutor(1, "Non-BlockingExecutor", taskQueue);
                }

                @Override // com.android.volley.AsyncRequestQueue.ExecutorFactory
                public ExecutorService createBlockingExecutor(BlockingQueue<Runnable> taskQueue) {
                    return getNewThreadPoolExecutor(4, "BlockingExecutor", taskQueue);
                }

                @Override // com.android.volley.AsyncRequestQueue.ExecutorFactory
                public ScheduledExecutorService createNonBlockingScheduledExecutor() {
                    return new ScheduledThreadPoolExecutor(0, getThreadFactory("ScheduledExecutor"));
                }

                private ThreadPoolExecutor getNewThreadPoolExecutor(int maximumPoolSize, String threadNameSuffix, BlockingQueue<Runnable> taskQueue) {
                    return new ThreadPoolExecutor(0, maximumPoolSize, 60L, TimeUnit.SECONDS, taskQueue, getThreadFactory(threadNameSuffix));
                }

                private ThreadFactory getThreadFactory(final String threadNameSuffix) {
                    return new ThreadFactory() { // from class: com.android.volley.AsyncRequestQueue.Builder.1.1
                        @Override // java.util.concurrent.ThreadFactory
                        public Thread newThread(Runnable runnable) {
                            Thread t = Executors.defaultThreadFactory().newThread(runnable);
                            t.setName("Volley-" + threadNameSuffix);
                            return t;
                        }
                    };
                }
            };
        }

        public AsyncRequestQueue build() {
            if (this.mCache == null && this.mAsyncCache == null) {
                throw new IllegalArgumentException("You must set one of the cache objects");
            }
            if (this.mCache == null) {
                this.mCache = new ThrowingCache();
            }
            if (this.mResponseDelivery == null) {
                this.mResponseDelivery = new ExecutorDelivery(new Handler(Looper.getMainLooper()));
            }
            if (this.mExecutorFactory == null) {
                this.mExecutorFactory = getDefaultExecutorFactory();
            }
            return new AsyncRequestQueue(this.mCache, this.mNetwork, this.mAsyncCache, this.mResponseDelivery, this.mExecutorFactory);
        }
    }

    /* loaded from: classes.dex */
    private static class ThrowingCache implements Cache {
        private ThrowingCache() {
        }

        @Override // com.android.volley.Cache
        public Cache.Entry get(String key) {
            throw new UnsupportedOperationException();
        }

        @Override // com.android.volley.Cache
        public void put(String key, Cache.Entry entry) {
            throw new UnsupportedOperationException();
        }

        @Override // com.android.volley.Cache
        public void initialize() {
            throw new UnsupportedOperationException();
        }

        @Override // com.android.volley.Cache
        public void invalidate(String key, boolean fullExpire) {
            throw new UnsupportedOperationException();
        }

        @Override // com.android.volley.Cache
        public void remove(String key) {
            throw new UnsupportedOperationException();
        }

        @Override // com.android.volley.Cache
        public void clear() {
            throw new UnsupportedOperationException();
        }
    }
}
