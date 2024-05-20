package com.android.volley.toolbox;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.widget.ImageView;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.ImageLoader;
/* loaded from: classes.dex */
public class NetworkImageView extends ImageView {
    private Bitmap mDefaultImageBitmap;
    private Drawable mDefaultImageDrawable;
    private int mDefaultImageId;
    private Bitmap mErrorImageBitmap;
    private Drawable mErrorImageDrawable;
    private int mErrorImageId;
    private ImageLoader.ImageContainer mImageContainer;
    private ImageLoader mImageLoader;
    private String mUrl;

    public NetworkImageView(Context context) {
        this(context, null);
    }

    public NetworkImageView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public NetworkImageView(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
    }

    public void setImageUrl(String url, ImageLoader imageLoader) {
        Threads.throwIfNotOnMainThread();
        this.mUrl = url;
        this.mImageLoader = imageLoader;
        loadImageIfNecessary(false);
    }

    public void setDefaultImageResId(int defaultImage) {
        this.mDefaultImageBitmap = null;
        this.mDefaultImageDrawable = null;
        this.mDefaultImageId = defaultImage;
    }

    public void setDefaultImageDrawable(Drawable defaultImageDrawable) {
        this.mDefaultImageId = 0;
        this.mDefaultImageBitmap = null;
        this.mDefaultImageDrawable = defaultImageDrawable;
    }

    public void setDefaultImageBitmap(Bitmap defaultImage) {
        this.mDefaultImageId = 0;
        this.mDefaultImageDrawable = null;
        this.mDefaultImageBitmap = defaultImage;
    }

    public void setErrorImageResId(int errorImage) {
        this.mErrorImageBitmap = null;
        this.mErrorImageDrawable = null;
        this.mErrorImageId = errorImage;
    }

    public void setErrorImageDrawable(Drawable errorImageDrawable) {
        this.mErrorImageId = 0;
        this.mErrorImageBitmap = null;
        this.mErrorImageDrawable = errorImageDrawable;
    }

    public void setErrorImageBitmap(Bitmap errorImage) {
        this.mErrorImageId = 0;
        this.mErrorImageDrawable = null;
        this.mErrorImageBitmap = errorImage;
    }

    void loadImageIfNecessary(boolean isInLayoutPass) {
        boolean wrapWidth;
        boolean wrapHeight;
        int width = getWidth();
        int height = getHeight();
        ImageView.ScaleType scaleType = getScaleType();
        boolean z = true;
        if (getLayoutParams() == null) {
            wrapWidth = false;
            wrapHeight = false;
        } else {
            boolean wrapWidth2 = getLayoutParams().width == -2;
            boolean wrapHeight2 = getLayoutParams().height == -2;
            wrapWidth = wrapWidth2;
            wrapHeight = wrapHeight2;
        }
        if (!wrapWidth || !wrapHeight) {
            z = false;
        }
        boolean isFullyWrapContent = z;
        if (width == 0 && height == 0 && !isFullyWrapContent) {
            return;
        }
        if (TextUtils.isEmpty(this.mUrl)) {
            if (this.mImageContainer != null) {
                this.mImageContainer.cancelRequest();
                this.mImageContainer = null;
            }
            setDefaultImageOrNull();
            return;
        }
        if (this.mImageContainer != null && this.mImageContainer.getRequestUrl() != null) {
            if (this.mImageContainer.getRequestUrl().equals(this.mUrl)) {
                return;
            }
            this.mImageContainer.cancelRequest();
            setDefaultImageOrNull();
        }
        int maxWidth = wrapWidth ? 0 : width;
        int maxHeight = wrapHeight ? 0 : height;
        this.mImageContainer = this.mImageLoader.get(this.mUrl, new AnonymousClass1(isInLayoutPass), maxWidth, maxHeight, scaleType);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: com.android.volley.toolbox.NetworkImageView$1  reason: invalid class name */
    /* loaded from: classes.dex */
    public class AnonymousClass1 implements ImageLoader.ImageListener {
        final /* synthetic */ boolean val$isInLayoutPass;

        AnonymousClass1(boolean z) {
            this.val$isInLayoutPass = z;
        }

        @Override // com.android.volley.Response.ErrorListener
        public void onErrorResponse(VolleyError error) {
            if (NetworkImageView.this.mErrorImageId != 0) {
                NetworkImageView.this.setImageResource(NetworkImageView.this.mErrorImageId);
            } else if (NetworkImageView.this.mErrorImageDrawable != null) {
                NetworkImageView.this.setImageDrawable(NetworkImageView.this.mErrorImageDrawable);
            } else if (NetworkImageView.this.mErrorImageBitmap != null) {
                NetworkImageView.this.setImageBitmap(NetworkImageView.this.mErrorImageBitmap);
            }
        }

        @Override // com.android.volley.toolbox.ImageLoader.ImageListener
        public void onResponse(final ImageLoader.ImageContainer response, boolean isImmediate) {
            if (isImmediate && this.val$isInLayoutPass) {
                NetworkImageView.this.post(new Runnable() { // from class: com.android.volley.toolbox.NetworkImageView.1.1
                    @Override // java.lang.Runnable
                    public void run() {
                        AnonymousClass1.this.onResponse(response, false);
                    }
                });
            } else if (response.getBitmap() == null) {
                if (NetworkImageView.this.mDefaultImageId != 0) {
                    NetworkImageView.this.setImageResource(NetworkImageView.this.mDefaultImageId);
                } else if (NetworkImageView.this.mDefaultImageDrawable != null) {
                    NetworkImageView.this.setImageDrawable(NetworkImageView.this.mDefaultImageDrawable);
                } else if (NetworkImageView.this.mDefaultImageBitmap != null) {
                    NetworkImageView.this.setImageBitmap(NetworkImageView.this.mDefaultImageBitmap);
                }
            } else {
                NetworkImageView.this.setImageBitmap(response.getBitmap());
            }
        }
    }

    private void setDefaultImageOrNull() {
        if (this.mDefaultImageId != 0) {
            setImageResource(this.mDefaultImageId);
        } else if (this.mDefaultImageDrawable != null) {
            setImageDrawable(this.mDefaultImageDrawable);
        } else if (this.mDefaultImageBitmap != null) {
            setImageBitmap(this.mDefaultImageBitmap);
        } else {
            setImageBitmap(null);
        }
    }

    @Override // android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        loadImageIfNecessary(true);
    }

    @Override // android.widget.ImageView, android.view.View
    protected void onDetachedFromWindow() {
        if (this.mImageContainer != null) {
            this.mImageContainer.cancelRequest();
            setImageBitmap(null);
            this.mImageContainer = null;
        }
        super.onDetachedFromWindow();
    }

    @Override // android.widget.ImageView, android.view.View
    protected void drawableStateChanged() {
        super.drawableStateChanged();
        invalidate();
    }
}
