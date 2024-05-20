package com.android.volley.toolbox;

import com.android.volley.AuthFailureError;
import com.android.volley.Request;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.http.Header;
import org.apache.http.ProtocolVersion;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicHttpResponse;
import org.apache.http.message.BasicStatusLine;
/* loaded from: classes.dex */
public abstract class BaseHttpStack implements HttpStack {
    public abstract HttpResponse executeRequest(Request<?> request, Map<String, String> map) throws IOException, AuthFailureError;

    @Override // com.android.volley.toolbox.HttpStack
    @Deprecated
    public final org.apache.http.HttpResponse performRequest(Request<?> request, Map<String, String> additionalHeaders) throws IOException, AuthFailureError {
        HttpResponse response = executeRequest(request, additionalHeaders);
        ProtocolVersion protocolVersion = new ProtocolVersion("HTTP", 1, 1);
        BasicHttpResponse apacheResponse = new BasicHttpResponse(new BasicStatusLine(protocolVersion, response.getStatusCode(), ""));
        List<Header> headers = new ArrayList<>();
        for (com.android.volley.Header header : response.getHeaders()) {
            headers.add(new BasicHeader(header.getName(), header.getValue()));
        }
        apacheResponse.setHeaders((Header[]) headers.toArray(new Header[0]));
        InputStream responseStream = response.getContent();
        if (responseStream != null) {
            BasicHttpEntity entity = new BasicHttpEntity();
            entity.setContent(responseStream);
            entity.setContentLength(response.getContentLength());
            apacheResponse.setEntity(entity);
        }
        return apacheResponse;
    }
}
