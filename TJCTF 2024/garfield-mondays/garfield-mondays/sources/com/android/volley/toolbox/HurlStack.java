package com.android.volley.toolbox;

import com.android.volley.AuthFailureError;
import com.android.volley.Header;
import com.android.volley.Request;
import com.android.volley.toolbox.HttpClientStack;
import java.io.DataOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
/* loaded from: classes.dex */
public class HurlStack extends BaseHttpStack {
    private static final int HTTP_CONTINUE = 100;
    private final SSLSocketFactory mSslSocketFactory;
    private final UrlRewriter mUrlRewriter;

    /* loaded from: classes.dex */
    public interface UrlRewriter extends com.android.volley.toolbox.UrlRewriter {
    }

    public HurlStack() {
        this(null);
    }

    public HurlStack(UrlRewriter urlRewriter) {
        this(urlRewriter, null);
    }

    public HurlStack(UrlRewriter urlRewriter, SSLSocketFactory sslSocketFactory) {
        this.mUrlRewriter = urlRewriter;
        this.mSslSocketFactory = sslSocketFactory;
    }

    @Override // com.android.volley.toolbox.BaseHttpStack
    public HttpResponse executeRequest(Request<?> request, Map<String, String> additionalHeaders) throws IOException, AuthFailureError {
        String url = request.getUrl();
        HashMap<String, String> map = new HashMap<>();
        map.putAll(additionalHeaders);
        map.putAll(request.getHeaders());
        if (this.mUrlRewriter != null) {
            String rewritten = this.mUrlRewriter.rewriteUrl(url);
            if (rewritten == null) {
                throw new IOException("URL blocked by rewriter: " + url);
            }
            url = rewritten;
        }
        URL parsedUrl = new URL(url);
        HttpURLConnection connection = openConnection(parsedUrl, request);
        try {
            for (String headerName : map.keySet()) {
                connection.setRequestProperty(headerName, map.get(headerName));
            }
            setConnectionParametersForRequest(connection, request);
            int responseCode = connection.getResponseCode();
            if (responseCode == -1) {
                throw new IOException("Could not retrieve response code from HttpUrlConnection.");
            }
            if (!hasResponseBody(request.getMethod(), responseCode)) {
                return new HttpResponse(responseCode, convertHeaders(connection.getHeaderFields()));
            }
            HttpResponse httpResponse = new HttpResponse(responseCode, convertHeaders(connection.getHeaderFields()), connection.getContentLength(), createInputStream(request, connection));
            if (1 == 0) {
                connection.disconnect();
            }
            return httpResponse;
        } finally {
            if (0 == 0) {
                connection.disconnect();
            }
        }
    }

    static List<Header> convertHeaders(Map<String, List<String>> responseHeaders) {
        List<Header> headerList = new ArrayList<>(responseHeaders.size());
        for (Map.Entry<String, List<String>> entry : responseHeaders.entrySet()) {
            if (entry.getKey() != null) {
                for (String value : entry.getValue()) {
                    headerList.add(new Header(entry.getKey(), value));
                }
            }
        }
        return headerList;
    }

    private static boolean hasResponseBody(int requestMethod, int responseCode) {
        return (requestMethod == 4 || (100 <= responseCode && responseCode < 200) || responseCode == 204 || responseCode == 304) ? false : true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class UrlConnectionInputStream extends FilterInputStream {
        private final HttpURLConnection mConnection;

        UrlConnectionInputStream(HttpURLConnection connection) {
            super(HurlStack.inputStreamFromConnection(connection));
            this.mConnection = connection;
        }

        @Override // java.io.FilterInputStream, java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
        public void close() throws IOException {
            super.close();
            this.mConnection.disconnect();
        }
    }

    protected InputStream createInputStream(Request<?> request, HttpURLConnection connection) {
        return new UrlConnectionInputStream(connection);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static InputStream inputStreamFromConnection(HttpURLConnection connection) {
        try {
            InputStream inputStream = connection.getInputStream();
            return inputStream;
        } catch (IOException e) {
            InputStream inputStream2 = connection.getErrorStream();
            return inputStream2;
        }
    }

    protected HttpURLConnection createConnection(URL url) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setInstanceFollowRedirects(HttpURLConnection.getFollowRedirects());
        return connection;
    }

    private HttpURLConnection openConnection(URL url, Request<?> request) throws IOException {
        HttpURLConnection connection = createConnection(url);
        int timeoutMs = request.getTimeoutMs();
        connection.setConnectTimeout(timeoutMs);
        connection.setReadTimeout(timeoutMs);
        connection.setUseCaches(false);
        connection.setDoInput(true);
        if ("https".equals(url.getProtocol()) && this.mSslSocketFactory != null) {
            ((HttpsURLConnection) connection).setSSLSocketFactory(this.mSslSocketFactory);
        }
        return connection;
    }

    void setConnectionParametersForRequest(HttpURLConnection connection, Request<?> request) throws IOException, AuthFailureError {
        switch (request.getMethod()) {
            case -1:
                byte[] postBody = request.getPostBody();
                if (postBody != null) {
                    connection.setRequestMethod("POST");
                    addBody(connection, request, postBody);
                    return;
                }
                return;
            case 0:
                connection.setRequestMethod("GET");
                return;
            case 1:
                connection.setRequestMethod("POST");
                addBodyIfExists(connection, request);
                return;
            case 2:
                connection.setRequestMethod("PUT");
                addBodyIfExists(connection, request);
                return;
            case 3:
                connection.setRequestMethod("DELETE");
                return;
            case 4:
                connection.setRequestMethod("HEAD");
                return;
            case 5:
                connection.setRequestMethod("OPTIONS");
                return;
            case 6:
                connection.setRequestMethod("TRACE");
                return;
            case 7:
                connection.setRequestMethod(HttpClientStack.HttpPatch.METHOD_NAME);
                addBodyIfExists(connection, request);
                return;
            default:
                throw new IllegalStateException("Unknown method type.");
        }
    }

    private void addBodyIfExists(HttpURLConnection connection, Request<?> request) throws IOException, AuthFailureError {
        byte[] body = request.getBody();
        if (body != null) {
            addBody(connection, request, body);
        }
    }

    private void addBody(HttpURLConnection connection, Request<?> request, byte[] body) throws IOException {
        connection.setDoOutput(true);
        if (!connection.getRequestProperties().containsKey(HttpHeaderParser.HEADER_CONTENT_TYPE)) {
            connection.setRequestProperty(HttpHeaderParser.HEADER_CONTENT_TYPE, request.getBodyContentType());
        }
        DataOutputStream out = new DataOutputStream(createOutputStream(request, connection, body.length));
        out.write(body);
        out.close();
    }

    protected OutputStream createOutputStream(Request<?> request, HttpURLConnection connection, int length) throws IOException {
        return connection.getOutputStream();
    }
}
