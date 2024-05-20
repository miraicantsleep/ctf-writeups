package com.android.volley.toolbox;

import com.android.volley.AuthFailureError;
import com.android.volley.Request;
import com.android.volley.VolleyLog;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicReference;
/* loaded from: classes.dex */
public abstract class AsyncHttpStack extends BaseHttpStack {
    private ExecutorService mBlockingExecutor;
    private ExecutorService mNonBlockingExecutor;

    /* loaded from: classes.dex */
    public interface OnRequestComplete {
        void onAuthError(AuthFailureError authFailureError);

        void onError(IOException iOException);

        void onSuccess(HttpResponse httpResponse);
    }

    public abstract void executeRequest(Request<?> request, Map<String, String> map, OnRequestComplete onRequestComplete);

    public void setNonBlockingExecutor(ExecutorService executor) {
        this.mNonBlockingExecutor = executor;
    }

    public void setBlockingExecutor(ExecutorService executor) {
        this.mBlockingExecutor = executor;
    }

    protected ExecutorService getBlockingExecutor() {
        return this.mBlockingExecutor;
    }

    protected ExecutorService getNonBlockingExecutor() {
        return this.mNonBlockingExecutor;
    }

    @Override // com.android.volley.toolbox.BaseHttpStack
    public final HttpResponse executeRequest(Request<?> request, Map<String, String> additionalHeaders) throws IOException, AuthFailureError {
        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicReference<Response> entry = new AtomicReference<>();
        executeRequest(request, additionalHeaders, new OnRequestComplete() { // from class: com.android.volley.toolbox.AsyncHttpStack.1
            @Override // com.android.volley.toolbox.AsyncHttpStack.OnRequestComplete
            public void onSuccess(HttpResponse httpResponse) {
                Response response = new Response(httpResponse, null, null);
                entry.set(response);
                latch.countDown();
            }

            @Override // com.android.volley.toolbox.AsyncHttpStack.OnRequestComplete
            public void onAuthError(AuthFailureError authFailureError) {
                Response response = new Response(null, null, authFailureError);
                entry.set(response);
                latch.countDown();
            }

            @Override // com.android.volley.toolbox.AsyncHttpStack.OnRequestComplete
            public void onError(IOException ioException) {
                Response response = new Response(null, ioException, null);
                entry.set(response);
                latch.countDown();
            }
        });
        try {
            latch.await();
            Response response = entry.get();
            if (response.httpResponse != null) {
                return response.httpResponse;
            }
            if (response.ioException != null) {
                throw response.ioException;
            }
            throw response.authFailureError;
        } catch (InterruptedException e) {
            VolleyLog.e(e, "while waiting for CountDownLatch", new Object[0]);
            Thread.currentThread().interrupt();
            throw new InterruptedIOException(e.toString());
        }
    }

    /* loaded from: classes.dex */
    private static class Response {
        AuthFailureError authFailureError;
        HttpResponse httpResponse;
        IOException ioException;

        private Response(HttpResponse httpResponse, IOException ioException, AuthFailureError authFailureError) {
            this.httpResponse = httpResponse;
            this.ioException = ioException;
            this.authFailureError = authFailureError;
        }
    }
}
