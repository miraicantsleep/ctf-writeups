package com.android.volley.toolbox;

import android.os.SystemClock;
import android.text.TextUtils;
import com.android.volley.Cache;
import com.android.volley.Header;
import com.android.volley.VolleyLog;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
/* loaded from: classes.dex */
public class DiskBasedCache implements Cache {
    private static final int CACHE_MAGIC = 538247942;
    private static final int DEFAULT_DISK_USAGE_BYTES = 5242880;
    static final float HYSTERESIS_FACTOR = 0.9f;
    private final Map<String, CacheHeader> mEntries;
    private final int mMaxCacheSizeInBytes;
    private final FileSupplier mRootDirectorySupplier;
    private long mTotalSize;

    /* loaded from: classes.dex */
    public interface FileSupplier {
        File get();
    }

    public DiskBasedCache(final File rootDirectory, int maxCacheSizeInBytes) {
        this.mEntries = new LinkedHashMap(16, 0.75f, true);
        this.mTotalSize = 0L;
        this.mRootDirectorySupplier = new FileSupplier() { // from class: com.android.volley.toolbox.DiskBasedCache.1
            @Override // com.android.volley.toolbox.DiskBasedCache.FileSupplier
            public File get() {
                return rootDirectory;
            }
        };
        this.mMaxCacheSizeInBytes = maxCacheSizeInBytes;
    }

    public DiskBasedCache(FileSupplier rootDirectorySupplier, int maxCacheSizeInBytes) {
        this.mEntries = new LinkedHashMap(16, 0.75f, true);
        this.mTotalSize = 0L;
        this.mRootDirectorySupplier = rootDirectorySupplier;
        this.mMaxCacheSizeInBytes = maxCacheSizeInBytes;
    }

    public DiskBasedCache(File rootDirectory) {
        this(rootDirectory, (int) DEFAULT_DISK_USAGE_BYTES);
    }

    public DiskBasedCache(FileSupplier rootDirectorySupplier) {
        this(rootDirectorySupplier, (int) DEFAULT_DISK_USAGE_BYTES);
    }

    @Override // com.android.volley.Cache
    public synchronized void clear() {
        File[] files = this.mRootDirectorySupplier.get().listFiles();
        if (files != null) {
            for (File file : files) {
                file.delete();
            }
        }
        this.mEntries.clear();
        this.mTotalSize = 0L;
        VolleyLog.d("Cache cleared.", new Object[0]);
    }

    @Override // com.android.volley.Cache
    public synchronized Cache.Entry get(String key) {
        CacheHeader entry = this.mEntries.get(key);
        if (entry == null) {
            return null;
        }
        File file = getFileForKey(key);
        try {
            CountingInputStream cis = new CountingInputStream(new BufferedInputStream(createInputStream(file)), file.length());
            try {
                CacheHeader entryOnDisk = CacheHeader.readHeader(cis);
                if (!TextUtils.equals(key, entryOnDisk.key)) {
                    VolleyLog.d("%s: key=%s, found=%s", file.getAbsolutePath(), key, entryOnDisk.key);
                    removeEntry(key);
                    return null;
                }
                byte[] data = streamToBytes(cis, cis.bytesRemaining());
                return entry.toCacheEntry(data);
            } finally {
                cis.close();
            }
        } catch (IOException e) {
            VolleyLog.d("%s: %s", file.getAbsolutePath(), e.toString());
            remove(key);
            return null;
        }
    }

    @Override // com.android.volley.Cache
    public synchronized void initialize() {
        File rootDirectory = this.mRootDirectorySupplier.get();
        if (!rootDirectory.exists()) {
            if (!rootDirectory.mkdirs()) {
                VolleyLog.e("Unable to create cache dir %s", rootDirectory.getAbsolutePath());
            }
            return;
        }
        File[] files = rootDirectory.listFiles();
        if (files == null) {
            return;
        }
        for (File file : files) {
            try {
                long entrySize = file.length();
                CountingInputStream cis = new CountingInputStream(new BufferedInputStream(createInputStream(file)), entrySize);
                try {
                    CacheHeader entry = CacheHeader.readHeader(cis);
                    entry.size = entrySize;
                    putEntry(entry.key, entry);
                    cis.close();
                } catch (Throwable th) {
                    cis.close();
                    throw th;
                    break;
                }
            } catch (IOException e) {
                file.delete();
            }
        }
    }

    @Override // com.android.volley.Cache
    public synchronized void invalidate(String key, boolean fullExpire) {
        Cache.Entry entry = get(key);
        if (entry != null) {
            entry.softTtl = 0L;
            if (fullExpire) {
                entry.ttl = 0L;
            }
            put(key, entry);
        }
    }

    @Override // com.android.volley.Cache
    public synchronized void put(String key, Cache.Entry entry) {
        BufferedOutputStream fos;
        CacheHeader e;
        boolean success;
        if (this.mTotalSize + entry.data.length <= this.mMaxCacheSizeInBytes || entry.data.length <= this.mMaxCacheSizeInBytes * HYSTERESIS_FACTOR) {
            File file = getFileForKey(key);
            try {
                fos = new BufferedOutputStream(createOutputStream(file));
                e = new CacheHeader(key, entry);
                success = e.writeHeader(fos);
            } catch (IOException e2) {
                boolean deleted = file.delete();
                if (!deleted) {
                    VolleyLog.d("Could not clean up file %s", file.getAbsolutePath());
                }
                initializeIfRootDirectoryDeleted();
            }
            if (!success) {
                fos.close();
                VolleyLog.d("Failed to write header for %s", file.getAbsolutePath());
                throw new IOException();
            }
            fos.write(entry.data);
            fos.close();
            e.size = file.length();
            putEntry(key, e);
            pruneIfNeeded();
        }
    }

    @Override // com.android.volley.Cache
    public synchronized void remove(String key) {
        boolean deleted = getFileForKey(key).delete();
        removeEntry(key);
        if (!deleted) {
            VolleyLog.d("Could not delete cache entry for key=%s, filename=%s", key, getFilenameForKey(key));
        }
    }

    private String getFilenameForKey(String key) {
        int firstHalfLength = key.length() / 2;
        String localFilename = String.valueOf(key.substring(0, firstHalfLength).hashCode());
        return localFilename + String.valueOf(key.substring(firstHalfLength).hashCode());
    }

    public File getFileForKey(String key) {
        return new File(this.mRootDirectorySupplier.get(), getFilenameForKey(key));
    }

    private void initializeIfRootDirectoryDeleted() {
        if (!this.mRootDirectorySupplier.get().exists()) {
            VolleyLog.d("Re-initializing cache after external clearing.", new Object[0]);
            this.mEntries.clear();
            this.mTotalSize = 0L;
            initialize();
        }
    }

    private void pruneIfNeeded() {
        if (this.mTotalSize < this.mMaxCacheSizeInBytes) {
            return;
        }
        if (VolleyLog.DEBUG) {
            VolleyLog.v("Pruning old cache entries.", new Object[0]);
        }
        long before = this.mTotalSize;
        int prunedFiles = 0;
        long startTime = SystemClock.elapsedRealtime();
        Iterator<Map.Entry<String, CacheHeader>> iterator = this.mEntries.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, CacheHeader> entry = iterator.next();
            CacheHeader e = entry.getValue();
            boolean deleted = getFileForKey(e.key).delete();
            if (deleted) {
                this.mTotalSize -= e.size;
            } else {
                VolleyLog.d("Could not delete cache entry for key=%s, filename=%s", e.key, getFilenameForKey(e.key));
            }
            iterator.remove();
            prunedFiles++;
            if (((float) this.mTotalSize) < this.mMaxCacheSizeInBytes * HYSTERESIS_FACTOR) {
                break;
            }
        }
        if (VolleyLog.DEBUG) {
            VolleyLog.v("pruned %d files, %d bytes, %d ms", Integer.valueOf(prunedFiles), Long.valueOf(this.mTotalSize - before), Long.valueOf(SystemClock.elapsedRealtime() - startTime));
        }
    }

    private void putEntry(String key, CacheHeader entry) {
        if (!this.mEntries.containsKey(key)) {
            this.mTotalSize += entry.size;
        } else {
            CacheHeader oldEntry = this.mEntries.get(key);
            this.mTotalSize += entry.size - oldEntry.size;
        }
        this.mEntries.put(key, entry);
    }

    private void removeEntry(String key) {
        CacheHeader removed = this.mEntries.remove(key);
        if (removed != null) {
            this.mTotalSize -= removed.size;
        }
    }

    static byte[] streamToBytes(CountingInputStream cis, long length) throws IOException {
        long maxLength = cis.bytesRemaining();
        if (length < 0 || length > maxLength || ((int) length) != length) {
            throw new IOException("streamToBytes length=" + length + ", maxLength=" + maxLength);
        }
        byte[] bytes = new byte[(int) length];
        new DataInputStream(cis).readFully(bytes);
        return bytes;
    }

    InputStream createInputStream(File file) throws FileNotFoundException {
        return new FileInputStream(file);
    }

    OutputStream createOutputStream(File file) throws FileNotFoundException {
        return new FileOutputStream(file);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class CacheHeader {
        final List<Header> allResponseHeaders;
        final String etag;
        final String key;
        final long lastModified;
        final long serverDate;
        long size;
        final long softTtl;
        final long ttl;

        private CacheHeader(String key, String etag, long serverDate, long lastModified, long ttl, long softTtl, List<Header> allResponseHeaders) {
            this.key = key;
            this.etag = "".equals(etag) ? null : etag;
            this.serverDate = serverDate;
            this.lastModified = lastModified;
            this.ttl = ttl;
            this.softTtl = softTtl;
            this.allResponseHeaders = allResponseHeaders;
        }

        CacheHeader(String key, Cache.Entry entry) {
            this(key, entry.etag, entry.serverDate, entry.lastModified, entry.ttl, entry.softTtl, getAllResponseHeaders(entry));
        }

        private static List<Header> getAllResponseHeaders(Cache.Entry entry) {
            if (entry.allResponseHeaders != null) {
                return entry.allResponseHeaders;
            }
            return HttpHeaderParser.toAllHeaderList(entry.responseHeaders);
        }

        static CacheHeader readHeader(CountingInputStream is) throws IOException {
            int magic = DiskBasedCache.readInt(is);
            if (magic != DiskBasedCache.CACHE_MAGIC) {
                throw new IOException();
            }
            String key = DiskBasedCache.readString(is);
            String etag = DiskBasedCache.readString(is);
            long serverDate = DiskBasedCache.readLong(is);
            long lastModified = DiskBasedCache.readLong(is);
            long ttl = DiskBasedCache.readLong(is);
            long softTtl = DiskBasedCache.readLong(is);
            List<Header> allResponseHeaders = DiskBasedCache.readHeaderList(is);
            return new CacheHeader(key, etag, serverDate, lastModified, ttl, softTtl, allResponseHeaders);
        }

        Cache.Entry toCacheEntry(byte[] data) {
            Cache.Entry e = new Cache.Entry();
            e.data = data;
            e.etag = this.etag;
            e.serverDate = this.serverDate;
            e.lastModified = this.lastModified;
            e.ttl = this.ttl;
            e.softTtl = this.softTtl;
            e.responseHeaders = HttpHeaderParser.toHeaderMap(this.allResponseHeaders);
            e.allResponseHeaders = Collections.unmodifiableList(this.allResponseHeaders);
            return e;
        }

        boolean writeHeader(OutputStream os) {
            try {
                DiskBasedCache.writeInt(os, DiskBasedCache.CACHE_MAGIC);
                DiskBasedCache.writeString(os, this.key);
                DiskBasedCache.writeString(os, this.etag == null ? "" : this.etag);
                DiskBasedCache.writeLong(os, this.serverDate);
                DiskBasedCache.writeLong(os, this.lastModified);
                DiskBasedCache.writeLong(os, this.ttl);
                DiskBasedCache.writeLong(os, this.softTtl);
                DiskBasedCache.writeHeaderList(this.allResponseHeaders, os);
                os.flush();
                return true;
            } catch (IOException e) {
                VolleyLog.d("%s", e.toString());
                return false;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class CountingInputStream extends FilterInputStream {
        private long bytesRead;
        private final long length;

        CountingInputStream(InputStream in, long length) {
            super(in);
            this.length = length;
        }

        @Override // java.io.FilterInputStream, java.io.InputStream
        public int read() throws IOException {
            int result = super.read();
            if (result != -1) {
                this.bytesRead++;
            }
            return result;
        }

        @Override // java.io.FilterInputStream, java.io.InputStream
        public int read(byte[] buffer, int offset, int count) throws IOException {
            int result = super.read(buffer, offset, count);
            if (result != -1) {
                this.bytesRead += result;
            }
            return result;
        }

        long bytesRead() {
            return this.bytesRead;
        }

        long bytesRemaining() {
            return this.length - this.bytesRead;
        }
    }

    private static int read(InputStream is) throws IOException {
        int b = is.read();
        if (b == -1) {
            throw new EOFException();
        }
        return b;
    }

    static void writeInt(OutputStream os, int n) throws IOException {
        os.write((n >> 0) & 255);
        os.write((n >> 8) & 255);
        os.write((n >> 16) & 255);
        os.write((n >> 24) & 255);
    }

    static int readInt(InputStream is) throws IOException {
        int n = 0 | (read(is) << 0);
        return n | (read(is) << 8) | (read(is) << 16) | (read(is) << 24);
    }

    static void writeLong(OutputStream os, long n) throws IOException {
        os.write((byte) (n >>> 0));
        os.write((byte) (n >>> 8));
        os.write((byte) (n >>> 16));
        os.write((byte) (n >>> 24));
        os.write((byte) (n >>> 32));
        os.write((byte) (n >>> 40));
        os.write((byte) (n >>> 48));
        os.write((byte) (n >>> 56));
    }

    static long readLong(InputStream is) throws IOException {
        long n = 0 | ((read(is) & 255) << 0);
        return n | ((read(is) & 255) << 8) | ((read(is) & 255) << 16) | ((read(is) & 255) << 24) | ((read(is) & 255) << 32) | ((read(is) & 255) << 40) | ((read(is) & 255) << 48) | ((read(is) & 255) << 56);
    }

    static void writeString(OutputStream os, String s) throws IOException {
        byte[] b = s.getBytes("UTF-8");
        writeLong(os, b.length);
        os.write(b, 0, b.length);
    }

    static String readString(CountingInputStream cis) throws IOException {
        long n = readLong(cis);
        byte[] b = streamToBytes(cis, n);
        return new String(b, "UTF-8");
    }

    static void writeHeaderList(List<Header> headers, OutputStream os) throws IOException {
        if (headers != null) {
            writeInt(os, headers.size());
            for (Header header : headers) {
                writeString(os, header.getName());
                writeString(os, header.getValue());
            }
            return;
        }
        writeInt(os, 0);
    }

    static List<Header> readHeaderList(CountingInputStream cis) throws IOException {
        int size = readInt(cis);
        if (size < 0) {
            throw new IOException("readHeaderList size=" + size);
        }
        List<Header> result = size == 0 ? Collections.emptyList() : new ArrayList<>();
        for (int i = 0; i < size; i++) {
            String name = readString(cis).intern();
            String value = readString(cis).intern();
            result.add(new Header(name, value));
        }
        return result;
    }
}
