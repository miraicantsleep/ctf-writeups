package com.tjctf.garfieldmondays;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.util.AttributeSet;
import android.view.View;
import android.widget.ImageView;
import androidx.core.view.InputDeviceCompat;
import androidx.core.view.ViewCompat;
/* loaded from: classes3.dex */
public class GarfieldView extends View {
    ImageView garfield;
    private Paint paintBody;
    private Paint paintFeatures;
    private Paint paintPink;
    private Paint paintStripes;
    private Paint paintWhite;
    private Paint paintYellow;
    private Paint paintYellow2;

    public GarfieldView(Context context) {
        super(context);
        init();
    }

    public GarfieldView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    public GarfieldView(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
        init();
    }

    @Override // android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        this.garfield.animate().x(getWidth() * 0.565f).y(getHeight() * 0.165f).setDuration(1500L);
    }

    private void init() {
        this.paintBody = new Paint(1);
        this.paintBody.setColor(Color.parseColor("#FFA500"));
        this.paintBody.setStyle(Paint.Style.FILL);
        this.paintFeatures = new Paint();
        this.paintFeatures.setColor(ViewCompat.MEASURED_STATE_MASK);
        this.paintFeatures.setStyle(Paint.Style.STROKE);
        this.paintFeatures.setStrokeWidth(5.0f);
        this.paintStripes = new Paint();
        this.paintStripes.setColor(ViewCompat.MEASURED_STATE_MASK);
        this.paintStripes.setStyle(Paint.Style.FILL);
        this.paintWhite = new Paint();
        this.paintWhite.setColor(-1);
        this.paintWhite.setStyle(Paint.Style.FILL);
        this.paintPink = new Paint();
        this.paintPink.setColor(Color.parseColor("#FFC0CB"));
        this.paintPink.setStyle(Paint.Style.FILL);
        this.paintYellow = new Paint();
        this.paintYellow.setColor(InputDeviceCompat.SOURCE_ANY);
        this.paintYellow.setStyle(Paint.Style.FILL);
        this.paintYellow2 = new Paint();
        this.paintYellow2.setColor(Color.parseColor("#FFC594"));
        this.paintYellow2.setStyle(Paint.Style.FILL);
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float centerX = getWidth() / 2.0f;
        float centerY = getHeight() / 2.0f;
        Path bodyPath = new Path();
        bodyPath.addOval(centerX - 150.0f, centerY - 200.0f, centerX + 150.0f, centerY + 200.0f, Path.Direction.CW);
        canvas.drawPath(bodyPath, this.paintBody);
        Path middleBodyPath = new Path();
        middleBodyPath.addOval(centerX - 100.0f, centerY - 150.0f, centerX + 100.0f, centerY + 150.0f, Path.Direction.CW);
        canvas.drawPath(middleBodyPath, this.paintYellow2);
        canvas.drawCircle(centerX, centerY - 250.0f, 120.0f, this.paintBody);
        canvas.drawCircle(centerX - 50.0f, centerY - 270.0f, 30.0f, this.paintWhite);
        canvas.drawCircle(centerX + 50.0f, centerY - 270.0f, 30.0f, this.paintWhite);
        canvas.drawCircle(centerX - 50.0f, centerY - 270.0f, 15.0f, this.paintStripes);
        canvas.drawCircle(centerX + 50.0f, centerY - 270.0f, 15.0f, this.paintStripes);
        canvas.drawCircle(centerX, centerY - 230.0f, 10.0f, this.paintPink);
        canvas.drawArc(centerX - 60.0f, centerY - 220.0f, centerX, centerY - 180.0f, 180.0f, 140.0f, false, this.paintYellow);
        canvas.drawArc(centerX, centerY - 220.0f, centerX + 60.0f, centerY - 180.0f, 0.0f, -140.0f, false, this.paintYellow);
        drawEar1(canvas, centerX - 80.0f, centerY - 340.0f, this.paintBody);
        drawEar2(canvas, centerX + 80.0f, centerY - 340.0f, this.paintBody);
        Path tailPath = new Path();
        tailPath.moveTo(centerX - 100.0f, centerY + 50.0f);
        tailPath.lineTo(centerX - 250.0f, centerY - 20.0f);
        tailPath.lineTo(centerX - 220.0f, centerY + 70.0f);
        tailPath.lineTo(centerX - 100.0f, centerY + 120.0f);
        tailPath.close();
        canvas.drawPath(tailPath, this.paintBody);
        canvas.drawArc(centerX - 250.0f, centerY - 90.0f, centerX - 170.0f, centerY + 70.0f, 180.0f, -110.0f, false, this.paintStripes);
        drawPaw(canvas, centerX - 100.0f, centerY + 150.0f, this.paintBody);
        drawPaw(canvas, centerX + 100.0f, 150.0f + centerY, this.paintBody);
        canvas.drawOval(centerX - 180.0f, centerY - 120.0f, centerX - 80.0f, centerY - 60.0f, this.paintBody);
        canvas.drawOval(centerX + 180.0f, centerY - 120.0f, centerX + 80.0f, centerY - 60.0f, this.paintBody);
        Path whiskerPath1 = new Path();
        whiskerPath1.moveTo(centerX - 90.0f, centerY - 300.0f);
        whiskerPath1.lineTo(centerX - 130.0f, centerY - 330.0f);
        whiskerPath1.close();
        canvas.drawPath(whiskerPath1, this.paintFeatures);
        Path whiskerPath2 = new Path();
        whiskerPath2.moveTo(centerX - 100.0f, centerY - 270.0f);
        whiskerPath2.lineTo(centerX - 140.0f, centerY - 300.0f);
        whiskerPath2.close();
        canvas.drawPath(whiskerPath2, this.paintFeatures);
        Path whiskerPath3 = new Path();
        whiskerPath3.moveTo(centerX + 90.0f, centerY - 300.0f);
        whiskerPath3.lineTo(130.0f + centerX, centerY - 330.0f);
        whiskerPath3.close();
        canvas.drawPath(whiskerPath3, this.paintFeatures);
        Path whiskerPath4 = new Path();
        whiskerPath4.moveTo(centerX + 100.0f, centerY - 270.0f);
        whiskerPath4.lineTo(140.0f + centerX, centerY - 300.0f);
        whiskerPath4.close();
        canvas.drawPath(whiskerPath4, this.paintFeatures);
    }

    private void drawEar1(Canvas canvas, float x, float y, Paint paint) {
        Path path = new Path();
        path.moveTo(x, y);
        path.lineTo(x, y - 70.0f);
        path.lineTo(50.0f + x, y - 20.0f);
        path.close();
        canvas.drawPath(path, paint);
    }

    private void drawEar2(Canvas canvas, float x, float y, Paint paint) {
        Path path = new Path();
        path.moveTo(x, y);
        path.lineTo(x, y - 70.0f);
        path.lineTo(x - 50.0f, y - 20.0f);
        path.close();
        canvas.drawPath(path, paint);
    }

    private void drawPaw(Canvas canvas, float x, float y, Paint paint) {
        canvas.drawOval(x - 50.0f, y - 30.0f, x + 50.0f, y + 30.0f, paint);
    }
}
