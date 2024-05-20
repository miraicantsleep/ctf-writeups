package com.android.volley.toolbox;

import android.os.SystemClock;
import com.android.volley.AsyncNetwork;
import com.android.volley.AuthFailureError;
import com.android.volley.Header;
import com.android.volley.NetworkResponse;
import com.android.volley.Request;
import com.android.volley.RequestTask;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.AsyncHttpStack;
import com.android.volley.toolbox.NetworkUtility;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
/* loaded from: classes.dex */
public class BasicAsyncNetwork extends AsyncNetwork {
    private final AsyncHttpStack mAsyncStack;
    private final ByteArrayPool mPool;

    private BasicAsyncNetwork(AsyncHttpStack httpStack, ByteArrayPool pool) {
        this.mAsyncStack = httpStack;
        this.mPool = pool;
    }

    @Override // com.android.volley.AsyncNetwork
    public void setBlockingExecutor(ExecutorService executor) {
        super.setBlockingExecutor(executor);
        this.mAsyncStack.setBlockingExecutor(executor);
    }

    @Override // com.android.volley.AsyncNetwork
    public void setNonBlockingExecutor(ExecutorService executor) {
        super.setNonBlockingExecutor(executor);
        this.mAsyncStack.setNonBlockingExecutor(executor);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onRequestSucceeded(Request<?> request, long requestStartMs, HttpResponse httpResponse, AsyncNetwork.OnRequestComplete callback) {
        byte[] responseContents;
        int statusCode = httpResponse.getStatusCode();
        List<Header> responseHeaders = httpResponse.getHeaders();
        if (statusCode == 304) {
            long requestDuration = SystemClock.elapsedRealtime() - requestStartMs;
            callback.onSuccess(NetworkUtility.getNotModifiedNetworkResponse(request, requestDuration, responseHeaders));
            return;
        }
        byte[] responseContents2 = httpResponse.getContentBytes();
        if (responseContents2 == null && httpResponse.getContent() == null) {
            responseContents = new byte[0];
        } else {
            responseContents = responseContents2;
        }
        if (responseContents != null) {
            onResponseRead(requestStartMs, statusCode, httpResponse, request, callback, responseHeaders, responseContents);
            return;
        }
        InputStream inputStream = httpResponse.getContent();
        getBlockingExecutor().execute(new ResponseParsingTask(inputStream, httpResponse, request, callback, requestStartMs, responseHeaders, statusCode));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onRequestFailed(Request<?> request, AsyncNetwork.OnRequestComplete callback, IOException exception, long requestStartMs, HttpResponse httpResponse, byte[] responseContents) {
        try {
            NetworkUtility.RetryInfo retryInfo = NetworkUtility.shouldRetryException(request, exception, requestStartMs, httpResponse, responseContents);
            getBlockingExecutor().execute(new InvokeRetryPolicyTask(request, retryInfo, callback));
        } catch (VolleyError volleyError) {
            callback.onError(volleyError);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class InvokeRetryPolicyTask<T> extends RequestTask<T> {
        final AsyncNetwork.OnRequestComplete callback;
        final Request<T> request;
        final NetworkUtility.RetryInfo retryInfo;

        InvokeRetryPolicyTask(Request<T> request, NetworkUtility.RetryInfo retryInfo, AsyncNetwork.OnRequestComplete callback) {
            super(request);
            this.request = request;
            this.retryInfo = retryInfo;
            this.callback = callback;
        }

        @Override // java.lang.Runnable
        public void run() {
            try {
                NetworkUtility.attemptRetryOnException(this.request, this.retryInfo);
                BasicAsyncNetwork.this.performRequest(this.request, this.callback);
            } catch (VolleyError e) {
                this.callback.onError(e);
            }
        }
    }

    @Override // com.android.volley.AsyncNetwork
    public void performRequest(final Request<?> request, final AsyncNetwork.OnRequestComplete callback) {
        if (getBlockingExecutor() == null) {
            throw new IllegalStateException("mBlockingExecuter must be set before making a request");
        }
        final long requestStartMs = SystemClock.elapsedRealtime();
        Map<String, String> additionalRequestHeaders = HttpHeaderParser.getCacheHeaders(request.getCacheEntry());
        this.mAsyncStack.executeRequest(request, additionalRequestHeaders, new AsyncHttpStack.OnRequestComplete() { // from class: com.android.volley.toolbox.BasicAsyncNetwork.1
            @Override // com.android.volley.toolbox.AsyncHttpStack.OnRequestComplete
            public void onSuccess(HttpResponse httpResponse) {
                BasicAsyncNetwork.this.onRequestSucceeded(request, requestStartMs, httpResponse, callback);
            }

            @Override // com.android.volley.toolbox.AsyncHttpStack.OnRequestComplete
            public void onAuthError(AuthFailureError authFailureError) {
                callback.onError(authFailureError);
            }

            @Override // com.android.volley.toolbox.AsyncHttpStack.OnRequestComplete
            public void onError(IOException ioException) {
                BasicAsyncNetwork.this.onRequestFailed(request, callback, ioException, requestStartMs, null, null);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onResponseRead(long requestStartMs, int statusCode, HttpResponse httpResponse, Request<?> request, AsyncNetwork.OnRequestComplete callback, List<Header> responseHeaders, byte[] responseContents) {
        long requestLifetime = SystemClock.elapsedRealtime() - requestStartMs;
        NetworkUtility.logSlowRequests(requestLifetime, request, responseContents, statusCode);
        if (statusCode >= 200 && statusCode <= 299) {
            callback.onSuccess(new NetworkResponse(statusCode, responseContents, false, SystemClock.elapsedRealtime() - requestStartMs, responseHeaders));
            return;
        }
        onRequestFailed(request, callback, new IOException(), requestStartMs, httpResponse, responseContents);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class ResponseParsingTask<T> extends RequestTask<T> {
        AsyncNetwork.OnRequestComplete callback;
        HttpResponse httpResponse;
        InputStream inputStream;
        Request<T> request;
        long requestStartMs;
        List<Header> responseHeaders;
        int statusCode;

        ResponseParsingTask(InputStream inputStream, HttpResponse httpResponse, Request<T> request, AsyncNetwork.OnRequestComplete callback, long requestStartMs, List<Header> responseHeaders, int statusCode) {
            super(request);
            this.inputStream = inputStream;
            this.httpResponse = httpResponse;
            this.request = request;
            this.callback = callback;
            this.requestStartMs = requestStartMs;
            this.responseHeaders = responseHeaders;
            this.statusCode = statusCode;
        }

        @Override // java.lang.Runnable
        public void run() {
            try {
                byte[] finalResponseContents = NetworkUtility.inputStreamToBytes(this.inputStream, this.httpResponse.getContentLength(), BasicAsyncNetwork.this.mPool);
                BasicAsyncNetwork.this.onResponseRead(this.requestStartMs, this.statusCode, this.httpResponse, this.request, this.callback, this.responseHeaders, finalResponseContents);
            } catch (IOException e) {
                BasicAsyncNetwork.this.onRequestFailed(this.request, this.callback, e, this.requestStartMs, this.httpResponse, null);
            }
        }
    }

    /* loaded from: classes.dex */
    public static class Builder {
        private static final int DEFAULT_POOL_SIZE = 4096;
        private AsyncHttpStack mAsyncStack;
        private ByteArrayPool mPool = null;

        public Builder(AsyncHttpStack httpStack) {
            this.mAsyncStack = httpStack;
        }

        public Builder setPool(ByteArrayPool pool) {
            this.mPool = pool;
            return this;
        }

        public BasicAsyncNetwork build() {
            if (this.mPool == null) {
                this.mPool = new ByteArrayPool(4096);
            }
            return new BasicAsyncNetwork(this.mAsyncStack, this.mPool);
        }
    }
}
