package androidx.constraintlayout.utils.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Outline;
import android.graphics.Path;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.LayerDrawable;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewOutlineProvider;
import android.widget.ImageView;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.appcompat.widget.AppCompatImageButton;
import androidx.constraintlayout.utils.widget.ImageFilterView;
import androidx.constraintlayout.widget.R;
/* loaded from: classes.dex */
public class ImageFilterButton extends AppCompatImageButton {
    private Drawable mAltDrawable;
    private float mCrossfade;
    private Drawable mDrawable;
    private ImageFilterView.ImageMatrix mImageMatrix;
    LayerDrawable mLayer;
    Drawable[] mLayers;
    private boolean mOverlay;
    private float mPanX;
    private float mPanY;
    private Path mPath;
    RectF mRect;
    private float mRotate;
    private float mRound;
    private float mRoundPercent;
    ViewOutlineProvider mViewOutlineProvider;
    private float mZoom;

    public ImageFilterButton(Context context) {
        super(context);
        this.mImageMatrix = new ImageFilterView.ImageMatrix();
        this.mCrossfade = 0.0f;
        this.mRoundPercent = 0.0f;
        this.mRound = Float.NaN;
        this.mLayers = new Drawable[2];
        this.mOverlay = true;
        this.mAltDrawable = null;
        this.mDrawable = null;
        this.mPanX = Float.NaN;
        this.mPanY = Float.NaN;
        this.mZoom = Float.NaN;
        this.mRotate = Float.NaN;
        init(context, null);
    }

    public ImageFilterButton(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.mImageMatrix = new ImageFilterView.ImageMatrix();
        this.mCrossfade = 0.0f;
        this.mRoundPercent = 0.0f;
        this.mRound = Float.NaN;
        this.mLayers = new Drawable[2];
        this.mOverlay = true;
        this.mAltDrawable = null;
        this.mDrawable = null;
        this.mPanX = Float.NaN;
        this.mPanY = Float.NaN;
        this.mZoom = Float.NaN;
        this.mRotate = Float.NaN;
        init(context, attrs);
    }

    public ImageFilterButton(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mImageMatrix = new ImageFilterView.ImageMatrix();
        this.mCrossfade = 0.0f;
        this.mRoundPercent = 0.0f;
        this.mRound = Float.NaN;
        this.mLayers = new Drawable[2];
        this.mOverlay = true;
        this.mAltDrawable = null;
        this.mDrawable = null;
        this.mPanX = Float.NaN;
        this.mPanY = Float.NaN;
        this.mZoom = Float.NaN;
        this.mRotate = Float.NaN;
        init(context, attrs);
    }

    private void init(Context context, AttributeSet attrs) {
        setPadding(0, 0, 0, 0);
        if (attrs != null) {
            TypedArray a = getContext().obtainStyledAttributes(attrs, R.styleable.ImageFilterView);
            int N = a.getIndexCount();
            this.mAltDrawable = a.getDrawable(R.styleable.ImageFilterView_altSrc);
            for (int i = 0; i < N; i++) {
                int attr = a.getIndex(i);
                if (attr == R.styleable.ImageFilterView_crossfade) {
                    this.mCrossfade = a.getFloat(attr, 0.0f);
                } else if (attr == R.styleable.ImageFilterView_warmth) {
                    setWarmth(a.getFloat(attr, 0.0f));
                } else if (attr == R.styleable.ImageFilterView_saturation) {
                    setSaturation(a.getFloat(attr, 0.0f));
                } else if (attr == R.styleable.ImageFilterView_contrast) {
                    setContrast(a.getFloat(attr, 0.0f));
                } else if (attr == R.styleable.ImageFilterView_round) {
                    setRound(a.getDimension(attr, 0.0f));
                } else if (attr == R.styleable.ImageFilterView_roundPercent) {
                    setRoundPercent(a.getFloat(attr, 0.0f));
                } else if (attr == R.styleable.ImageFilterView_overlay) {
                    setOverlay(a.getBoolean(attr, this.mOverlay));
                } else if (attr == R.styleable.ImageFilterView_imagePanX) {
                    setImagePanX(a.getFloat(attr, this.mPanX));
                } else if (attr == R.styleable.ImageFilterView_imagePanY) {
                    setImagePanY(a.getFloat(attr, this.mPanY));
                } else if (attr == R.styleable.ImageFilterView_imageRotate) {
                    setImageRotate(a.getFloat(attr, this.mRotate));
                } else if (attr == R.styleable.ImageFilterView_imageZoom) {
                    setImageZoom(a.getFloat(attr, this.mZoom));
                }
            }
            a.recycle();
            this.mDrawable = getDrawable();
            if (this.mAltDrawable != null && this.mDrawable != null) {
                Drawable[] drawableArr = this.mLayers;
                Drawable mutate = getDrawable().mutate();
                this.mDrawable = mutate;
                drawableArr[0] = mutate;
                this.mLayers[1] = this.mAltDrawable.mutate();
                this.mLayer = new LayerDrawable(this.mLayers);
                this.mLayer.getDrawable(1).setAlpha((int) (this.mCrossfade * 255.0f));
                if (!this.mOverlay) {
                    this.mLayer.getDrawable(0).setAlpha((int) ((1.0f - this.mCrossfade) * 255.0f));
                }
                super.setImageDrawable(this.mLayer);
                return;
            }
            this.mDrawable = getDrawable();
            if (this.mDrawable != null) {
                Drawable[] drawableArr2 = this.mLayers;
                Drawable mutate2 = this.mDrawable.mutate();
                this.mDrawable = mutate2;
                drawableArr2[0] = mutate2;
            }
        }
    }

    public float getImagePanX() {
        return this.mPanX;
    }

    public float getImagePanY() {
        return this.mPanY;
    }

    public float getImageZoom() {
        return this.mZoom;
    }

    public float getImageRotate() {
        return this.mRotate;
    }

    public void setImagePanX(float pan) {
        this.mPanX = pan;
        updateViewMatrix();
    }

    public void setImagePanY(float pan) {
        this.mPanY = pan;
        updateViewMatrix();
    }

    public void setImageZoom(float zoom) {
        this.mZoom = zoom;
        updateViewMatrix();
    }

    public void setImageRotate(float rotation) {
        this.mRotate = rotation;
        updateViewMatrix();
    }

    @Override // androidx.appcompat.widget.AppCompatImageButton, android.widget.ImageView
    public void setImageDrawable(Drawable drawable) {
        if (this.mAltDrawable != null && drawable != null) {
            this.mDrawable = drawable.mutate();
            this.mLayers[0] = this.mDrawable;
            this.mLayers[1] = this.mAltDrawable;
            this.mLayer = new LayerDrawable(this.mLayers);
            super.setImageDrawable(this.mLayer);
            setCrossfade(this.mCrossfade);
            return;
        }
        super.setImageDrawable(drawable);
    }

    @Override // androidx.appcompat.widget.AppCompatImageButton, android.widget.ImageView
    public void setImageResource(int resId) {
        if (this.mAltDrawable != null) {
            this.mDrawable = AppCompatResources.getDrawable(getContext(), resId).mutate();
            this.mLayers[0] = this.mDrawable;
            this.mLayers[1] = this.mAltDrawable;
            this.mLayer = new LayerDrawable(this.mLayers);
            super.setImageDrawable(this.mLayer);
            setCrossfade(this.mCrossfade);
            return;
        }
        super.setImageResource(resId);
    }

    public void setAltImageResource(int resId) {
        this.mAltDrawable = AppCompatResources.getDrawable(getContext(), resId).mutate();
        this.mLayers[0] = this.mDrawable;
        this.mLayers[1] = this.mAltDrawable;
        this.mLayer = new LayerDrawable(this.mLayers);
        super.setImageDrawable(this.mLayer);
        setCrossfade(this.mCrossfade);
    }

    private void updateViewMatrix() {
        if (Float.isNaN(this.mPanX) && Float.isNaN(this.mPanY) && Float.isNaN(this.mZoom) && Float.isNaN(this.mRotate)) {
            setScaleType(ImageView.ScaleType.FIT_CENTER);
        } else {
            setMatrix();
        }
    }

    private void setMatrix() {
        if (Float.isNaN(this.mPanX) && Float.isNaN(this.mPanY) && Float.isNaN(this.mZoom) && Float.isNaN(this.mRotate)) {
            return;
        }
        float panX = Float.isNaN(this.mPanX) ? 0.0f : this.mPanX;
        float panY = Float.isNaN(this.mPanY) ? 0.0f : this.mPanY;
        float zoom = Float.isNaN(this.mZoom) ? 1.0f : this.mZoom;
        float rota = Float.isNaN(this.mRotate) ? 0.0f : this.mRotate;
        Matrix imageMatrix = new Matrix();
        imageMatrix.reset();
        float iw = getDrawable().getIntrinsicWidth();
        float ih = getDrawable().getIntrinsicHeight();
        float sw = getWidth();
        float sh = getHeight();
        float scale = (iw * sh < ih * sw ? sw / iw : sh / ih) * zoom;
        imageMatrix.postScale(scale, scale);
        float tx = ((((sw - (scale * iw)) * panX) + sw) - (scale * iw)) * 0.5f;
        float ty = ((((sh - (scale * ih)) * panY) + sh) - (scale * ih)) * 0.5f;
        imageMatrix.postTranslate(tx, ty);
        imageMatrix.postRotate(rota, sw / 2.0f, sh / 2.0f);
        setImageMatrix(imageMatrix);
        setScaleType(ImageView.ScaleType.MATRIX);
    }

    private void setOverlay(boolean overlay) {
        this.mOverlay = overlay;
    }

    public void setSaturation(float saturation) {
        this.mImageMatrix.mSaturation = saturation;
        this.mImageMatrix.updateMatrix(this);
    }

    public float getSaturation() {
        return this.mImageMatrix.mSaturation;
    }

    public void setContrast(float contrast) {
        this.mImageMatrix.mContrast = contrast;
        this.mImageMatrix.updateMatrix(this);
    }

    public float getContrast() {
        return this.mImageMatrix.mContrast;
    }

    public void setWarmth(float warmth) {
        this.mImageMatrix.mWarmth = warmth;
        this.mImageMatrix.updateMatrix(this);
    }

    public float getWarmth() {
        return this.mImageMatrix.mWarmth;
    }

    public void setCrossfade(float crossfade) {
        this.mCrossfade = crossfade;
        if (this.mLayers != null) {
            if (!this.mOverlay) {
                this.mLayer.getDrawable(0).setAlpha((int) ((1.0f - this.mCrossfade) * 255.0f));
            }
            this.mLayer.getDrawable(1).setAlpha((int) (this.mCrossfade * 255.0f));
            super.setImageDrawable(this.mLayer);
        }
    }

    public float getCrossfade() {
        return this.mCrossfade;
    }

    public void setBrightness(float brightness) {
        this.mImageMatrix.mBrightness = brightness;
        this.mImageMatrix.updateMatrix(this);
    }

    public void setRoundPercent(float round) {
        boolean change = this.mRoundPercent != round;
        this.mRoundPercent = round;
        if (this.mRoundPercent != 0.0f) {
            if (this.mPath == null) {
                this.mPath = new Path();
            }
            if (this.mRect == null) {
                this.mRect = new RectF();
            }
            if (this.mViewOutlineProvider == null) {
                this.mViewOutlineProvider = new ViewOutlineProvider() { // from class: androidx.constraintlayout.utils.widget.ImageFilterButton.1
                    @Override // android.view.ViewOutlineProvider
                    public void getOutline(View view, Outline outline) {
                        int w = ImageFilterButton.this.getWidth();
                        int h = ImageFilterButton.this.getHeight();
                        float r = (Math.min(w, h) * ImageFilterButton.this.mRoundPercent) / 2.0f;
                        outline.setRoundRect(0, 0, w, h, r);
                    }
                };
                setOutlineProvider(this.mViewOutlineProvider);
            }
            setClipToOutline(true);
            int w = getWidth();
            int h = getHeight();
            float r = (Math.min(w, h) * this.mRoundPercent) / 2.0f;
            this.mRect.set(0.0f, 0.0f, w, h);
            this.mPath.reset();
            this.mPath.addRoundRect(this.mRect, r, r, Path.Direction.CW);
        } else {
            setClipToOutline(false);
        }
        if (change) {
            invalidateOutline();
        }
    }

    public void setRound(float round) {
        if (Float.isNaN(round)) {
            this.mRound = round;
            float tmp = this.mRoundPercent;
            this.mRoundPercent = -1.0f;
            setRoundPercent(tmp);
            return;
        }
        float tmp2 = this.mRound;
        boolean change = tmp2 != round;
        this.mRound = round;
        if (this.mRound != 0.0f) {
            if (this.mPath == null) {
                this.mPath = new Path();
            }
            if (this.mRect == null) {
                this.mRect = new RectF();
            }
            if (this.mViewOutlineProvider == null) {
                this.mViewOutlineProvider = new ViewOutlineProvider() { // from class: androidx.constraintlayout.utils.widget.ImageFilterButton.2
                    @Override // android.view.ViewOutlineProvider
                    public void getOutline(View view, Outline outline) {
                        int w = ImageFilterButton.this.getWidth();
                        int h = ImageFilterButton.this.getHeight();
                        outline.setRoundRect(0, 0, w, h, ImageFilterButton.this.mRound);
                    }
                };
                setOutlineProvider(this.mViewOutlineProvider);
            }
            setClipToOutline(true);
            int w = getWidth();
            int h = getHeight();
            this.mRect.set(0.0f, 0.0f, w, h);
            this.mPath.reset();
            this.mPath.addRoundRect(this.mRect, this.mRound, this.mRound, Path.Direction.CW);
        } else {
            setClipToOutline(false);
        }
        if (change) {
            invalidateOutline();
        }
    }

    public float getRoundPercent() {
        return this.mRoundPercent;
    }

    public float getRound() {
        return this.mRound;
    }

    @Override // android.view.View
    public void draw(Canvas canvas) {
        super.draw(canvas);
        if (0 != 0) {
            canvas.restore();
        }
    }

    @Override // android.view.View
    public void layout(int l, int t, int r, int b) {
        super.layout(l, t, r, b);
        setMatrix();
    }
}
