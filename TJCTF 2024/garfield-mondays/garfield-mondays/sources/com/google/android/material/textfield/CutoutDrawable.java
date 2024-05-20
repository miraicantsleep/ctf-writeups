package com.google.android.material.textfield;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.view.View;
import com.google.android.material.shape.MaterialShapeDrawable;
import com.google.android.material.shape.ShapeAppearanceModel;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class CutoutDrawable extends MaterialShapeDrawable {
    CutoutDrawableState drawableState;

    /* JADX INFO: Access modifiers changed from: package-private */
    public static CutoutDrawable create(ShapeAppearanceModel shapeAppearanceModel) {
        return create(new CutoutDrawableState(shapeAppearanceModel != null ? shapeAppearanceModel : new ShapeAppearanceModel(), new RectF()));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static CutoutDrawable create(CutoutDrawableState drawableState) {
        return new ImplApi18(drawableState);
    }

    private CutoutDrawable(CutoutDrawableState drawableState) {
        super(drawableState);
        this.drawableState = drawableState;
    }

    @Override // com.google.android.material.shape.MaterialShapeDrawable, android.graphics.drawable.Drawable
    public Drawable mutate() {
        this.drawableState = new CutoutDrawableState(this.drawableState);
        return this;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean hasCutout() {
        return !this.drawableState.cutoutBounds.isEmpty();
    }

    void setCutout(float left, float top, float right, float bottom) {
        if (left == this.drawableState.cutoutBounds.left && top == this.drawableState.cutoutBounds.top && right == this.drawableState.cutoutBounds.right && bottom == this.drawableState.cutoutBounds.bottom) {
            return;
        }
        this.drawableState.cutoutBounds.set(left, top, right, bottom);
        invalidateSelf();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setCutout(RectF bounds) {
        setCutout(bounds.left, bounds.top, bounds.right, bounds.bottom);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void removeCutout() {
        setCutout(0.0f, 0.0f, 0.0f, 0.0f);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class ImplApi18 extends CutoutDrawable {
        ImplApi18(CutoutDrawableState drawableState) {
            super(drawableState);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.material.shape.MaterialShapeDrawable
        public void drawStrokeShape(Canvas canvas) {
            if (this.drawableState.cutoutBounds.isEmpty()) {
                super.drawStrokeShape(canvas);
                return;
            }
            canvas.save();
            canvas.clipOutRect(this.drawableState.cutoutBounds);
            super.drawStrokeShape(canvas);
            canvas.restore();
        }
    }

    /* loaded from: classes.dex */
    private static class ImplApi14 extends CutoutDrawable {
        private Paint cutoutPaint;
        private int savedLayer;

        ImplApi14(CutoutDrawableState drawableState) {
            super(drawableState);
        }

        @Override // com.google.android.material.shape.MaterialShapeDrawable, android.graphics.drawable.Drawable
        public void draw(Canvas canvas) {
            preDraw(canvas);
            super.draw(canvas);
            postDraw(canvas);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.material.shape.MaterialShapeDrawable
        public void drawStrokeShape(Canvas canvas) {
            super.drawStrokeShape(canvas);
            canvas.drawRect(this.drawableState.cutoutBounds, getCutoutPaint());
        }

        private Paint getCutoutPaint() {
            if (this.cutoutPaint == null) {
                this.cutoutPaint = new Paint(1);
                this.cutoutPaint.setStyle(Paint.Style.FILL_AND_STROKE);
                this.cutoutPaint.setColor(-1);
                this.cutoutPaint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.DST_OUT));
            }
            return this.cutoutPaint;
        }

        private void preDraw(Canvas canvas) {
            Drawable.Callback callback = getCallback();
            if (useHardwareLayer(callback)) {
                View viewCallback = (View) callback;
                if (viewCallback.getLayerType() != 2) {
                    viewCallback.setLayerType(2, null);
                    return;
                }
                return;
            }
            saveCanvasLayer(canvas);
        }

        private void saveCanvasLayer(Canvas canvas) {
            this.savedLayer = canvas.saveLayer(0.0f, 0.0f, canvas.getWidth(), canvas.getHeight(), null);
        }

        private void postDraw(Canvas canvas) {
            if (!useHardwareLayer(getCallback())) {
                canvas.restoreToCount(this.savedLayer);
            }
        }

        private boolean useHardwareLayer(Drawable.Callback callback) {
            return callback instanceof View;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static final class CutoutDrawableState extends MaterialShapeDrawable.MaterialShapeDrawableState {
        private final RectF cutoutBounds;

        private CutoutDrawableState(ShapeAppearanceModel shapeAppearanceModel, RectF cutoutBounds) {
            super(shapeAppearanceModel, null);
            this.cutoutBounds = cutoutBounds;
        }

        private CutoutDrawableState(CutoutDrawableState state) {
            super(state);
            this.cutoutBounds = state.cutoutBounds;
        }

        @Override // com.google.android.material.shape.MaterialShapeDrawable.MaterialShapeDrawableState, android.graphics.drawable.Drawable.ConstantState
        public Drawable newDrawable() {
            CutoutDrawable drawable = CutoutDrawable.create(this);
            drawable.invalidateSelf();
            return drawable;
        }
    }
}
