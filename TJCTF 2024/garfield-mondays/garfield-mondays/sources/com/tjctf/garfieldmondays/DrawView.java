package com.tjctf.garfieldmondays;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.util.AttributeSet;
import android.view.View;
/* loaded from: classes3.dex */
public class DrawView extends View {
    private int dY;
    private Paint p;
    private int y;

    public DrawView(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.p = new Paint();
        this.y = 0;
        this.dY = 5;
    }

    @Override // android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        this.p.setColor(Color.parseColor("#FFA500"));
        canvas.drawCircle(getWidth() / 2, this.y, 400.0f, this.p);
        canvas.drawCircle(100.0f, 200.0f, 150.5f, new Paint());
        this.y += this.dY;
        this.y %= getHeight();
        invalidate();
    }
}
