package com.tjctf.garfieldmondays;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.animation.LinearInterpolator;
import android.view.animation.RotateAnimation;
import android.widget.ImageView;
import androidx.appcompat.app.AppCompatActivity;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
/* loaded from: classes3.dex */
public class MainActivity extends AppCompatActivity {
    ImageView garfield;
    GarfieldView garfieldView;
    boolean isRotating = false;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        this.garfieldView = (GarfieldView) findViewById(R.id.garfieldView);
        this.garfield = (ImageView) findViewById(R.id.flag);
        this.garfieldView.garfield = this.garfield;
    }

    public void waveFlag(View view) {
        if (isTodayMonday()) {
            SimpleDateFormat sdf = new SimpleDateFormat("HH:mm", Locale.US);
            String currentTime = sdf.format(new Date());
            Log.i("FlagActivity", "Flag waved at: " + currentTime);
            String hashedTime = hashTime(currentTime);
            if ("cf4627b3786c8bad8cb855567bda362d8eca1809ea8839423682715cdf3aadad".equals(hashedTime)) {
                fetchSecrets(currentTime);
            }
        }
        RotateAnimation anim = new RotateAnimation(0.0f, 360.0f, 720.0f, 607.0f);
        RotateAnimation anim2 = new RotateAnimation(0.0f, -360.0f, 720.0f, 607.0f);
        anim.setInterpolator(new LinearInterpolator());
        anim2.setInterpolator(new LinearInterpolator());
        anim.setDuration(700L);
        anim2.setDuration(700L);
        if (!this.isRotating) {
            this.garfield.setAnimation(null);
            this.garfield.startAnimation(anim);
            this.isRotating = true;
            return;
        }
        this.garfield.setAnimation(null);
        this.garfield.startAnimation(anim2);
        this.isRotating = false;
    }

    public void fetchSecrets(String currentTime) {
        String modifiedTime = currentTime.replace(":", "");
        int timeAsInt = Integer.parseInt(modifiedTime);
        int calculatedValue = (timeAsInt * 100) + 225390;
        String result = modifiedTime + calculatedValue;
        Log.i("Login Info", "Username: garfield Password: " + TimeEncoder.encodeTime(result));
    }

    private String hashTime(String time) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(time.getBytes(StandardCharsets.UTF_8));
            BigInteger number = new BigInteger(1, hash);
            StringBuilder hexString = new StringBuilder(number.toString(16));
            while (hexString.length() < 32) {
                hexString.insert(0, '0');
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    public boolean isTodayMonday() {
        Calendar calendar = Calendar.getInstance();
        int dayOfWeek = calendar.get(7);
        return dayOfWeek == 2;
    }
}
