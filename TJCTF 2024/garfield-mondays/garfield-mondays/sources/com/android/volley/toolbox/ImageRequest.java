package com.android.volley.toolbox;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.widget.ImageView;
import com.android.volley.DefaultRetryPolicy;
import com.android.volley.NetworkResponse;
import com.android.volley.ParseError;
import com.android.volley.Request;
import com.android.volley.Response;
import com.android.volley.VolleyLog;
/* loaded from: classes.dex */
public class ImageRequest extends Request<Bitmap> {
    public static final float DEFAULT_IMAGE_BACKOFF_MULT = 2.0f;
    public static final int DEFAULT_IMAGE_MAX_RETRIES = 2;
    public static final int DEFAULT_IMAGE_TIMEOUT_MS = 1000;
    private static final Object sDecodeLock = new Object();
    private final Bitmap.Config mDecodeConfig;
    private Response.Listener<Bitmap> mListener;
    private final Object mLock;
    private final int mMaxHeight;
    private final int mMaxWidth;
    private final ImageView.ScaleType mScaleType;

    public ImageRequest(String url, Response.Listener<Bitmap> listener, int maxWidth, int maxHeight, ImageView.ScaleType scaleType, Bitmap.Config decodeConfig, Response.ErrorListener errorListener) {
        super(0, url, errorListener);
        this.mLock = new Object();
        setRetryPolicy(new DefaultRetryPolicy(1000, 2, 2.0f));
        this.mListener = listener;
        this.mDecodeConfig = decodeConfig;
        this.mMaxWidth = maxWidth;
        this.mMaxHeight = maxHeight;
        this.mScaleType = scaleType;
    }

    @Deprecated
    public ImageRequest(String url, Response.Listener<Bitmap> listener, int maxWidth, int maxHeight, Bitmap.Config decodeConfig, Response.ErrorListener errorListener) {
        this(url, listener, maxWidth, maxHeight, ImageView.ScaleType.CENTER_INSIDE, decodeConfig, errorListener);
    }

    @Override // com.android.volley.Request
    public Request.Priority getPriority() {
        return Request.Priority.LOW;
    }

    private static int getResizedDimension(int maxPrimary, int maxSecondary, int actualPrimary, int actualSecondary, ImageView.ScaleType scaleType) {
        if (maxPrimary == 0 && maxSecondary == 0) {
            return actualPrimary;
        }
        if (scaleType == ImageView.ScaleType.FIT_XY) {
            if (maxPrimary == 0) {
                return actualPrimary;
            }
            return maxPrimary;
        } else if (maxPrimary == 0) {
            return (int) (actualPrimary * (maxSecondary / actualSecondary));
        } else if (maxSecondary == 0) {
            return maxPrimary;
        } else {
            double ratio = actualSecondary / actualPrimary;
            if (scaleType == ImageView.ScaleType.CENTER_CROP) {
                if (maxPrimary * ratio >= maxSecondary) {
                    return maxPrimary;
                }
                int resized = (int) (maxSecondary / ratio);
                return resized;
            } else if (maxPrimary * ratio <= maxSecondary) {
                return maxPrimary;
            } else {
                int resized2 = (int) (maxSecondary / ratio);
                return resized2;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.android.volley.Request
    public Response<Bitmap> parseNetworkResponse(NetworkResponse response) {
        Response<Bitmap> doParse;
        synchronized (sDecodeLock) {
            try {
                try {
                    doParse = doParse(response);
                } catch (OutOfMemoryError e) {
                    VolleyLog.e("Caught OOM for %d byte image, url=%s", Integer.valueOf(response.data.length), getUrl());
                    return Response.error(new ParseError(e));
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return doParse;
    }

    private Response<Bitmap> doParse(NetworkResponse response) {
        Bitmap bitmap;
        byte[] data = response.data;
        BitmapFactory.Options decodeOptions = new BitmapFactory.Options();
        if (this.mMaxWidth == 0 && this.mMaxHeight == 0) {
            decodeOptions.inPreferredConfig = this.mDecodeConfig;
            bitmap = BitmapFactory.decodeByteArray(data, 0, data.length, decodeOptions);
        } else {
            decodeOptions.inJustDecodeBounds = true;
            BitmapFactory.decodeByteArray(data, 0, data.length, decodeOptions);
            int actualWidth = decodeOptions.outWidth;
            int actualHeight = decodeOptions.outHeight;
            int desiredWidth = getResizedDimension(this.mMaxWidth, this.mMaxHeight, actualWidth, actualHeight, this.mScaleType);
            int desiredHeight = getResizedDimension(this.mMaxHeight, this.mMaxWidth, actualHeight, actualWidth, this.mScaleType);
            decodeOptions.inJustDecodeBounds = false;
            decodeOptions.inSampleSize = findBestSampleSize(actualWidth, actualHeight, desiredWidth, desiredHeight);
            Bitmap tempBitmap = BitmapFactory.decodeByteArray(data, 0, data.length, decodeOptions);
            if (tempBitmap != null && (tempBitmap.getWidth() > desiredWidth || tempBitmap.getHeight() > desiredHeight)) {
                bitmap = Bitmap.createScaledBitmap(tempBitmap, desiredWidth, desiredHeight, true);
                tempBitmap.recycle();
            } else {
                bitmap = tempBitmap;
            }
        }
        if (bitmap == null) {
            return Response.error(new ParseError(response));
        }
        return Response.success(bitmap, HttpHeaderParser.parseCacheHeaders(response));
    }

    @Override // com.android.volley.Request
    public void cancel() {
        super.cancel();
        synchronized (this.mLock) {
            this.mListener = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.android.volley.Request
    public void deliverResponse(Bitmap response) {
        Response.Listener<Bitmap> listener;
        synchronized (this.mLock) {
            listener = this.mListener;
        }
        if (listener != null) {
            listener.onResponse(response);
        }
    }

    static int findBestSampleSize(int actualWidth, int actualHeight, int desiredWidth, int desiredHeight) {
        double wr = actualWidth / desiredWidth;
        double hr = actualHeight / desiredHeight;
        double ratio = Math.min(wr, hr);
        float n = 1.0f;
        while (n * 2.0f <= ratio) {
            n *= 2.0f;
        }
        return (int) n;
    }
}
