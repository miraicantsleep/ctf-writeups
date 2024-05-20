package com.android.volley.toolbox;

import com.android.volley.Header;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
/* loaded from: classes.dex */
public final class HttpResponse {
    private final InputStream mContent;
    private final byte[] mContentBytes;
    private final int mContentLength;
    private final List<Header> mHeaders;
    private final int mStatusCode;

    public HttpResponse(int statusCode, List<Header> headers) {
        this(statusCode, headers, -1, null);
    }

    public HttpResponse(int statusCode, List<Header> headers, int contentLength, InputStream content) {
        this.mStatusCode = statusCode;
        this.mHeaders = headers;
        this.mContentLength = contentLength;
        this.mContent = content;
        this.mContentBytes = null;
    }

    public HttpResponse(int statusCode, List<Header> headers, byte[] contentBytes) {
        this.mStatusCode = statusCode;
        this.mHeaders = headers;
        this.mContentLength = contentBytes.length;
        this.mContentBytes = contentBytes;
        this.mContent = null;
    }

    public final int getStatusCode() {
        return this.mStatusCode;
    }

    public final List<Header> getHeaders() {
        return Collections.unmodifiableList(this.mHeaders);
    }

    public final int getContentLength() {
        return this.mContentLength;
    }

    public final byte[] getContentBytes() {
        return this.mContentBytes;
    }

    public final InputStream getContent() {
        if (this.mContent != null) {
            return this.mContent;
        }
        if (this.mContentBytes != null) {
            return new ByteArrayInputStream(this.mContentBytes);
        }
        return null;
    }
}
