package com.google.android.material.textfield;

import android.text.method.PasswordTransformationMethod;
import android.view.View;
import android.widget.EditText;
import com.google.android.material.R;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class PasswordToggleEndIconDelegate extends EndIconDelegate {
    private EditText editText;
    private int iconResId;
    private final View.OnClickListener onIconClickListener;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$new$0$com-google-android-material-textfield-PasswordToggleEndIconDelegate  reason: not valid java name */
    public /* synthetic */ void m137x4cc26475(View view) {
        if (this.editText == null) {
            return;
        }
        int selection = this.editText.getSelectionEnd();
        if (hasPasswordTransformation()) {
            this.editText.setTransformationMethod(null);
        } else {
            this.editText.setTransformationMethod(PasswordTransformationMethod.getInstance());
        }
        if (selection >= 0) {
            this.editText.setSelection(selection);
        }
        refreshIconState();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public PasswordToggleEndIconDelegate(EndCompoundLayout endLayout, int overrideIconResId) {
        super(endLayout);
        this.iconResId = R.drawable.design_password_eye;
        this.onIconClickListener = new View.OnClickListener() { // from class: com.google.android.material.textfield.PasswordToggleEndIconDelegate$$ExternalSyntheticLambda0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                PasswordToggleEndIconDelegate.this.m137x4cc26475(view);
            }
        };
        if (overrideIconResId != 0) {
            this.iconResId = overrideIconResId;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public void setUp() {
        if (isInputTypePassword(this.editText)) {
            this.editText.setTransformationMethod(PasswordTransformationMethod.getInstance());
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public void tearDown() {
        if (this.editText != null) {
            this.editText.setTransformationMethod(PasswordTransformationMethod.getInstance());
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public int getIconDrawableResId() {
        return this.iconResId;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public int getIconContentDescriptionResId() {
        return R.string.password_toggle_content_description;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public boolean isIconCheckable() {
        return true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public boolean isIconChecked() {
        return !hasPasswordTransformation();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public View.OnClickListener getOnIconClickListener() {
        return this.onIconClickListener;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public void onEditTextAttached(EditText editText) {
        this.editText = editText;
        refreshIconState();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public void beforeEditTextChanged(CharSequence s, int start, int count, int after) {
        refreshIconState();
    }

    private boolean hasPasswordTransformation() {
        return this.editText != null && (this.editText.getTransformationMethod() instanceof PasswordTransformationMethod);
    }

    private static boolean isInputTypePassword(EditText editText) {
        return editText != null && (editText.getInputType() == 16 || editText.getInputType() == 128 || editText.getInputType() == 144 || editText.getInputType() == 224);
    }
}
