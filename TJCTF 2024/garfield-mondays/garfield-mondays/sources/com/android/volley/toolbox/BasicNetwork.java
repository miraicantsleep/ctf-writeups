package com.android.volley.toolbox;

import android.os.SystemClock;
import com.android.volley.Header;
import com.android.volley.Network;
import com.android.volley.NetworkResponse;
import com.android.volley.Request;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.NetworkUtility;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
/* loaded from: classes.dex */
public class BasicNetwork implements Network {
    private static final int DEFAULT_POOL_SIZE = 4096;
    private final BaseHttpStack mBaseHttpStack;
    @Deprecated
    protected final HttpStack mHttpStack;
    protected final ByteArrayPool mPool;

    @Deprecated
    public BasicNetwork(HttpStack httpStack) {
        this(httpStack, new ByteArrayPool(4096));
    }

    @Deprecated
    public BasicNetwork(HttpStack httpStack, ByteArrayPool pool) {
        this.mHttpStack = httpStack;
        this.mBaseHttpStack = new AdaptedHttpStack(httpStack);
        this.mPool = pool;
    }

    public BasicNetwork(BaseHttpStack httpStack) {
        this(httpStack, new ByteArrayPool(4096));
    }

    public BasicNetwork(BaseHttpStack httpStack, ByteArrayPool pool) {
        this.mBaseHttpStack = httpStack;
        this.mHttpStack = httpStack;
        this.mPool = pool;
    }

    @Override // com.android.volley.Network
    public NetworkResponse performRequest(Request<?> request) throws VolleyError {
        HttpResponse httpResponse;
        int statusCode;
        List<Header> responseHeaders;
        byte[] responseContents;
        long requestStart = SystemClock.elapsedRealtime();
        while (true) {
            Collections.emptyList();
            try {
                Map<String, String> additionalRequestHeaders = HttpHeaderParser.getCacheHeaders(request.getCacheEntry());
                httpResponse = this.mBaseHttpStack.executeRequest(request, additionalRequestHeaders);
                statusCode = httpResponse.getStatusCode();
                responseHeaders = httpResponse.getHeaders();
                break;
            } catch (IOException e) {
                NetworkUtility.RetryInfo retryInfo = NetworkUtility.shouldRetryException(request, e, requestStart, null, null);
                NetworkUtility.attemptRetryOnException(request, retryInfo);
            }
        }
        if (statusCode == 304) {
            long requestDuration = SystemClock.elapsedRealtime() - requestStart;
            return NetworkUtility.getNotModifiedNetworkResponse(request, requestDuration, responseHeaders);
        }
        InputStream inputStream = httpResponse.getContent();
        if (inputStream != null) {
            responseContents = NetworkUtility.inputStreamToBytes(inputStream, httpResponse.getContentLength(), this.mPool);
        } else {
            responseContents = new byte[0];
        }
        long requestLifetime = SystemClock.elapsedRealtime() - requestStart;
        NetworkUtility.logSlowRequests(requestLifetime, request, responseContents, statusCode);
        if (statusCode < 200 || statusCode > 299) {
            throw new IOException();
        }
        return new NetworkResponse(statusCode, responseContents, false, SystemClock.elapsedRealtime() - requestStart, responseHeaders);
    }

    @Deprecated
    protected static Map<String, String> convertHeaders(Header[] headers) {
        Map<String, String> result = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (int i = 0; i < headers.length; i++) {
            result.put(headers[i].getName(), headers[i].getValue());
        }
        return result;
    }
}
