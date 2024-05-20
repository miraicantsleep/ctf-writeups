package com.google.android.material.sidesheet;

import android.view.View;
/* loaded from: classes.dex */
public abstract class SideSheetCallback implements SheetCallback {
    @Override // com.google.android.material.sidesheet.SheetCallback
    public abstract void onSlide(View view, float f);

    @Override // com.google.android.material.sidesheet.SheetCallback
    public abstract void onStateChanged(View view, int i);

    /* JADX INFO: Access modifiers changed from: package-private */
    public void onLayout(View sheet) {
    }
}
