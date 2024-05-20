package com.android.volley.toolbox;

import com.android.volley.AuthFailureError;
import com.android.volley.Request;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.http.Header;
import org.apache.http.conn.ConnectTimeoutException;
/* loaded from: classes.dex */
class AdaptedHttpStack extends BaseHttpStack {
    private final HttpStack mHttpStack;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AdaptedHttpStack(HttpStack httpStack) {
        this.mHttpStack = httpStack;
    }

    @Override // com.android.volley.toolbox.BaseHttpStack
    public HttpResponse executeRequest(Request<?> request, Map<String, String> additionalHeaders) throws IOException, AuthFailureError {
        try {
            org.apache.http.HttpResponse apacheResp = this.mHttpStack.performRequest(request, additionalHeaders);
            int statusCode = apacheResp.getStatusLine().getStatusCode();
            Header[] headers = apacheResp.getAllHeaders();
            List<com.android.volley.Header> headerList = new ArrayList<>(headers.length);
            for (Header header : headers) {
                headerList.add(new com.android.volley.Header(header.getName(), header.getValue()));
            }
            if (apacheResp.getEntity() == null) {
                return new HttpResponse(statusCode, headerList);
            }
            long contentLength = apacheResp.getEntity().getContentLength();
            if (((int) contentLength) != contentLength) {
                throw new IOException("Response too large: " + contentLength);
            }
            return new HttpResponse(statusCode, headerList, (int) apacheResp.getEntity().getContentLength(), apacheResp.getEntity().getContent());
        } catch (ConnectTimeoutException e) {
            throw new SocketTimeoutException(e.getMessage());
        }
    }
}
