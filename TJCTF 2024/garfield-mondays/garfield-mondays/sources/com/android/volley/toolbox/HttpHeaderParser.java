package com.android.volley.toolbox;

import com.android.volley.Cache;
import com.android.volley.Header;
import com.android.volley.NetworkResponse;
import com.android.volley.VolleyLog;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.TreeSet;
/* loaded from: classes.dex */
public class HttpHeaderParser {
    private static final String DEFAULT_CONTENT_CHARSET = "ISO-8859-1";
    public static final String HEADER_CONTENT_TYPE = "Content-Type";
    private static final String RFC1123_OUTPUT_FORMAT = "EEE, dd MMM yyyy HH:mm:ss 'GMT'";
    private static final String RFC1123_PARSE_FORMAT = "EEE, dd MMM yyyy HH:mm:ss zzz";

    public static Cache.Entry parseCacheHeaders(NetworkResponse response) {
        long lastModified;
        boolean hasCacheControl;
        long lastModified2;
        long now = System.currentTimeMillis();
        Map<String, String> headers = response.headers;
        if (headers == null) {
            return null;
        }
        long serverDate = 0;
        long serverExpires = 0;
        long softExpire = 0;
        long finalExpire = 0;
        long maxAge = 0;
        long staleWhileRevalidate = 0;
        boolean mustRevalidate = false;
        String headerValue = headers.get("Date");
        if (headerValue != null) {
            serverDate = parseDateAsEpoch(headerValue);
        }
        String headerValue2 = headers.get("Cache-Control");
        if (headerValue2 != null) {
            lastModified = 0;
            String[] tokens = headerValue2.split(",", 0);
            int i = 0;
            while (i < tokens.length) {
                String headerValue3 = headerValue2;
                String token = tokens[i].trim();
                if (token.equals("no-cache") || token.equals("no-store")) {
                    return null;
                }
                if (token.startsWith("max-age=")) {
                    try {
                        maxAge = Long.parseLong(token.substring(8));
                    } catch (Exception e) {
                    }
                } else if (token.startsWith("stale-while-revalidate=")) {
                    try {
                        staleWhileRevalidate = Long.parseLong(token.substring(23));
                    } catch (Exception e2) {
                    }
                } else if (token.equals("must-revalidate") || token.equals("proxy-revalidate")) {
                    mustRevalidate = true;
                }
                i++;
                headerValue2 = headerValue3;
            }
            hasCacheControl = true;
        } else {
            lastModified = 0;
            hasCacheControl = false;
        }
        String headerValue4 = headers.get("Expires");
        if (headerValue4 != null) {
            serverExpires = parseDateAsEpoch(headerValue4);
        }
        String headerValue5 = headers.get("Last-Modified");
        if (headerValue5 == null) {
            lastModified2 = lastModified;
        } else {
            lastModified2 = parseDateAsEpoch(headerValue5);
        }
        String serverEtag = headers.get("ETag");
        if (hasCacheControl) {
            softExpire = now + (maxAge * 1000);
            finalExpire = mustRevalidate ? softExpire : softExpire + (1000 * staleWhileRevalidate);
        } else if (serverDate > 0 && serverExpires >= serverDate) {
            softExpire = now + (serverExpires - serverDate);
            finalExpire = softExpire;
        }
        Cache.Entry entry = new Cache.Entry();
        entry.data = response.data;
        entry.etag = serverEtag;
        entry.softTtl = softExpire;
        entry.ttl = finalExpire;
        entry.serverDate = serverDate;
        entry.lastModified = lastModified2;
        entry.responseHeaders = headers;
        entry.allResponseHeaders = response.allHeaders;
        return entry;
    }

    public static long parseDateAsEpoch(String dateStr) {
        try {
            return newUsGmtFormatter(RFC1123_PARSE_FORMAT).parse(dateStr).getTime();
        } catch (ParseException e) {
            if ("0".equals(dateStr) || "-1".equals(dateStr)) {
                VolleyLog.v("Unable to parse dateStr: %s, falling back to 0", dateStr);
                return 0L;
            }
            VolleyLog.e(e, "Unable to parse dateStr: %s, falling back to 0", dateStr);
            return 0L;
        }
    }

    static String formatEpochAsRfc1123(long epoch) {
        return newUsGmtFormatter(RFC1123_OUTPUT_FORMAT).format(new Date(epoch));
    }

    private static SimpleDateFormat newUsGmtFormatter(String format) {
        SimpleDateFormat formatter = new SimpleDateFormat(format, Locale.US);
        formatter.setTimeZone(TimeZone.getTimeZone("GMT"));
        return formatter;
    }

    public static String parseCharset(Map<String, String> headers, String defaultCharset) {
        if (headers == null) {
            return defaultCharset;
        }
        String contentType = headers.get(HEADER_CONTENT_TYPE);
        if (contentType != null) {
            String[] params = contentType.split(";", 0);
            for (int i = 1; i < params.length; i++) {
                String[] pair = params[i].trim().split("=", 0);
                if (pair.length == 2 && pair[0].equals("charset")) {
                    return pair[1];
                }
            }
        }
        return defaultCharset;
    }

    public static String parseCharset(Map<String, String> headers) {
        return parseCharset(headers, DEFAULT_CONTENT_CHARSET);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Map<String, String> toHeaderMap(List<Header> allHeaders) {
        Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (Header header : allHeaders) {
            headers.put(header.getName(), header.getValue());
        }
        return headers;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static List<Header> toAllHeaderList(Map<String, String> headers) {
        List<Header> allHeaders = new ArrayList<>(headers.size());
        for (Map.Entry<String, String> header : headers.entrySet()) {
            allHeaders.add(new Header(header.getKey(), header.getValue()));
        }
        return allHeaders;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static List<Header> combineHeaders(List<Header> responseHeaders, Cache.Entry entry) {
        Set<String> headerNamesFromNetworkResponse = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        if (!responseHeaders.isEmpty()) {
            for (Header header : responseHeaders) {
                headerNamesFromNetworkResponse.add(header.getName());
            }
        }
        List<Header> combinedHeaders = new ArrayList<>(responseHeaders);
        if (entry.allResponseHeaders != null) {
            if (!entry.allResponseHeaders.isEmpty()) {
                for (Header header2 : entry.allResponseHeaders) {
                    if (!headerNamesFromNetworkResponse.contains(header2.getName())) {
                        combinedHeaders.add(header2);
                    }
                }
            }
        } else if (!entry.responseHeaders.isEmpty()) {
            for (Map.Entry<String, String> header3 : entry.responseHeaders.entrySet()) {
                if (!headerNamesFromNetworkResponse.contains(header3.getKey())) {
                    combinedHeaders.add(new Header(header3.getKey(), header3.getValue()));
                }
            }
        }
        return combinedHeaders;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Map<String, String> getCacheHeaders(Cache.Entry entry) {
        if (entry == null) {
            return Collections.emptyMap();
        }
        Map<String, String> headers = new HashMap<>();
        if (entry.etag != null) {
            headers.put("If-None-Match", entry.etag);
        }
        if (entry.lastModified > 0) {
            headers.put("If-Modified-Since", formatEpochAsRfc1123(entry.lastModified));
        }
        return headers;
    }
}
