package com.google.android.material.textfield;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.TimeInterpolator;
import android.animation.ValueAnimator;
import android.graphics.drawable.Drawable;
import android.text.Editable;
import android.view.MotionEvent;
import android.view.View;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import android.widget.AutoCompleteTextView;
import android.widget.EditText;
import android.widget.Spinner;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityManagerCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import com.google.android.material.R;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.motion.MotionUtils;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class DropdownMenuEndIconDelegate extends EndIconDelegate {
    private static final int DEFAULT_ANIMATION_FADE_IN_DURATION = 67;
    private static final int DEFAULT_ANIMATION_FADE_OUT_DURATION = 50;
    private static final boolean IS_LOLLIPOP = true;
    private AccessibilityManager accessibilityManager;
    private final int animationFadeInDuration;
    private final TimeInterpolator animationFadeInterpolator;
    private final int animationFadeOutDuration;
    private AutoCompleteTextView autoCompleteTextView;
    private long dropdownPopupActivatedAt;
    private boolean dropdownPopupDirty;
    private boolean editTextHasFocus;
    private ValueAnimator fadeInAnim;
    private ValueAnimator fadeOutAnim;
    private boolean isEndIconChecked;
    private final View.OnFocusChangeListener onEditTextFocusChangeListener;
    private final View.OnClickListener onIconClickListener;
    private final AccessibilityManagerCompat.TouchExplorationStateChangeListener touchExplorationStateChangeListener;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$new$0$com-google-android-material-textfield-DropdownMenuEndIconDelegate  reason: not valid java name */
    public /* synthetic */ void m132xd03fedd4(View view) {
        showHideDropdown();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$new$1$com-google-android-material-textfield-DropdownMenuEndIconDelegate  reason: not valid java name */
    public /* synthetic */ void m133xac016995(View view, boolean hasFocus) {
        this.editTextHasFocus = hasFocus;
        refreshIconState();
        if (!hasFocus) {
            setEndIconChecked(false);
            this.dropdownPopupDirty = false;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$new$2$com-google-android-material-textfield-DropdownMenuEndIconDelegate  reason: not valid java name */
    public /* synthetic */ void m134x87c2e556(boolean enabled) {
        if (this.autoCompleteTextView != null && !EditTextUtils.isEditable(this.autoCompleteTextView)) {
            ViewCompat.setImportantForAccessibility(this.endIconView, enabled ? 2 : 1);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public DropdownMenuEndIconDelegate(EndCompoundLayout endLayout) {
        super(endLayout);
        this.onIconClickListener = new View.OnClickListener() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate$$ExternalSyntheticLambda0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                DropdownMenuEndIconDelegate.this.m132xd03fedd4(view);
            }
        };
        this.onEditTextFocusChangeListener = new View.OnFocusChangeListener() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate$$ExternalSyntheticLambda1
            @Override // android.view.View.OnFocusChangeListener
            public final void onFocusChange(View view, boolean z) {
                DropdownMenuEndIconDelegate.this.m133xac016995(view, z);
            }
        };
        this.touchExplorationStateChangeListener = new AccessibilityManagerCompat.TouchExplorationStateChangeListener() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate$$ExternalSyntheticLambda2
            @Override // androidx.core.view.accessibility.AccessibilityManagerCompat.TouchExplorationStateChangeListener
            public final void onTouchExplorationStateChanged(boolean z) {
                DropdownMenuEndIconDelegate.this.m134x87c2e556(z);
            }
        };
        this.dropdownPopupActivatedAt = Long.MAX_VALUE;
        this.animationFadeInDuration = MotionUtils.resolveThemeDuration(endLayout.getContext(), R.attr.motionDurationShort3, 67);
        this.animationFadeOutDuration = MotionUtils.resolveThemeDuration(endLayout.getContext(), R.attr.motionDurationShort3, 50);
        this.animationFadeInterpolator = MotionUtils.resolveThemeInterpolator(endLayout.getContext(), R.attr.motionEasingLinearInterpolator, AnimationUtils.LINEAR_INTERPOLATOR);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public void setUp() {
        initAnimators();
        this.accessibilityManager = (AccessibilityManager) this.context.getSystemService("accessibility");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public void tearDown() {
        if (this.autoCompleteTextView != null) {
            this.autoCompleteTextView.setOnTouchListener(null);
            if (IS_LOLLIPOP) {
                this.autoCompleteTextView.setOnDismissListener(null);
            }
        }
    }

    @Override // com.google.android.material.textfield.EndIconDelegate
    public AccessibilityManagerCompat.TouchExplorationStateChangeListener getTouchExplorationStateChangeListener() {
        return this.touchExplorationStateChangeListener;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public int getIconDrawableResId() {
        return IS_LOLLIPOP ? R.drawable.mtrl_dropdown_arrow : R.drawable.mtrl_ic_arrow_drop_down;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public int getIconContentDescriptionResId() {
        return R.string.exposed_dropdown_menu_content_description;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public boolean isIconCheckable() {
        return true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public boolean isIconChecked() {
        return this.isEndIconChecked;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public boolean isIconActivable() {
        return true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public boolean isIconActivated() {
        return this.editTextHasFocus;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public boolean shouldTintIconOnError() {
        return true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public boolean isBoxBackgroundModeSupported(int boxBackgroundMode) {
        return boxBackgroundMode != 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public View.OnClickListener getOnIconClickListener() {
        return this.onIconClickListener;
    }

    @Override // com.google.android.material.textfield.EndIconDelegate
    public void onEditTextAttached(EditText editText) {
        this.autoCompleteTextView = castAutoCompleteTextViewOrThrow(editText);
        setUpDropdownShowHideBehavior();
        this.textInputLayout.setErrorIconDrawable((Drawable) null);
        if (!EditTextUtils.isEditable(editText) && this.accessibilityManager.isTouchExplorationEnabled()) {
            ViewCompat.setImportantForAccessibility(this.endIconView, 2);
        }
        this.textInputLayout.setEndIconVisible(true);
    }

    @Override // com.google.android.material.textfield.EndIconDelegate
    public void afterEditTextChanged(Editable s) {
        if (this.accessibilityManager.isTouchExplorationEnabled() && EditTextUtils.isEditable(this.autoCompleteTextView) && !this.endIconView.hasFocus()) {
            this.autoCompleteTextView.dismissDropDown();
        }
        this.autoCompleteTextView.post(new Runnable() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate$$ExternalSyntheticLambda4
            @Override // java.lang.Runnable
            public final void run() {
                DropdownMenuEndIconDelegate.this.m130xae660ff2();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$afterEditTextChanged$3$com-google-android-material-textfield-DropdownMenuEndIconDelegate  reason: not valid java name */
    public /* synthetic */ void m130xae660ff2() {
        boolean isPopupShowing = this.autoCompleteTextView.isPopupShowing();
        setEndIconChecked(isPopupShowing);
        this.dropdownPopupDirty = isPopupShowing;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @Override // com.google.android.material.textfield.EndIconDelegate
    public View.OnFocusChangeListener getOnEditTextFocusChangeListener() {
        return this.onEditTextFocusChangeListener;
    }

    @Override // com.google.android.material.textfield.EndIconDelegate
    public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfoCompat info) {
        if (!EditTextUtils.isEditable(this.autoCompleteTextView)) {
            info.setClassName(Spinner.class.getName());
        }
        if (info.isShowingHintText()) {
            info.setHintText(null);
        }
    }

    @Override // com.google.android.material.textfield.EndIconDelegate
    public void onPopulateAccessibilityEvent(View host, AccessibilityEvent event) {
        if (!this.accessibilityManager.isEnabled() || EditTextUtils.isEditable(this.autoCompleteTextView)) {
            return;
        }
        boolean invalidState = event.getEventType() == 32768 && this.isEndIconChecked && !this.autoCompleteTextView.isPopupShowing();
        if (event.getEventType() == 1 || invalidState) {
            showHideDropdown();
            updateDropdownPopupDirty();
        }
    }

    private void showHideDropdown() {
        if (this.autoCompleteTextView == null) {
            return;
        }
        if (isDropdownPopupActive()) {
            this.dropdownPopupDirty = false;
        }
        if (!this.dropdownPopupDirty) {
            if (IS_LOLLIPOP) {
                setEndIconChecked(!this.isEndIconChecked);
            } else {
                this.isEndIconChecked = !this.isEndIconChecked;
                refreshIconState();
            }
            if (this.isEndIconChecked) {
                this.autoCompleteTextView.requestFocus();
                this.autoCompleteTextView.showDropDown();
                return;
            }
            this.autoCompleteTextView.dismissDropDown();
            return;
        }
        this.dropdownPopupDirty = false;
    }

    private void setUpDropdownShowHideBehavior() {
        this.autoCompleteTextView.setOnTouchListener(new View.OnTouchListener() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate$$ExternalSyntheticLambda5
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return DropdownMenuEndIconDelegate.this.m135x5f2e2537(view, motionEvent);
            }
        });
        if (IS_LOLLIPOP) {
            this.autoCompleteTextView.setOnDismissListener(new AutoCompleteTextView.OnDismissListener() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate$$ExternalSyntheticLambda6
                @Override // android.widget.AutoCompleteTextView.OnDismissListener
                public final void onDismiss() {
                    DropdownMenuEndIconDelegate.this.m136x3aefa0f8();
                }
            });
        }
        this.autoCompleteTextView.setThreshold(0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$setUpDropdownShowHideBehavior$4$com-google-android-material-textfield-DropdownMenuEndIconDelegate  reason: not valid java name */
    public /* synthetic */ boolean m135x5f2e2537(View view, MotionEvent event) {
        if (event.getAction() == 1) {
            if (isDropdownPopupActive()) {
                this.dropdownPopupDirty = false;
            }
            showHideDropdown();
            updateDropdownPopupDirty();
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$setUpDropdownShowHideBehavior$5$com-google-android-material-textfield-DropdownMenuEndIconDelegate  reason: not valid java name */
    public /* synthetic */ void m136x3aefa0f8() {
        updateDropdownPopupDirty();
        setEndIconChecked(false);
    }

    private boolean isDropdownPopupActive() {
        long activeFor = System.currentTimeMillis() - this.dropdownPopupActivatedAt;
        return activeFor < 0 || activeFor > 300;
    }

    private static AutoCompleteTextView castAutoCompleteTextViewOrThrow(EditText editText) {
        if (!(editText instanceof AutoCompleteTextView)) {
            throw new RuntimeException("EditText needs to be an AutoCompleteTextView if an Exposed Dropdown Menu is being used.");
        }
        return (AutoCompleteTextView) editText;
    }

    private void updateDropdownPopupDirty() {
        this.dropdownPopupDirty = true;
        this.dropdownPopupActivatedAt = System.currentTimeMillis();
    }

    private void setEndIconChecked(boolean checked) {
        if (this.isEndIconChecked != checked) {
            this.isEndIconChecked = checked;
            this.fadeInAnim.cancel();
            this.fadeOutAnim.start();
        }
    }

    private void initAnimators() {
        this.fadeInAnim = getAlphaAnimator(this.animationFadeInDuration, 0.0f, 1.0f);
        this.fadeOutAnim = getAlphaAnimator(this.animationFadeOutDuration, 1.0f, 0.0f);
        this.fadeOutAnim.addListener(new AnimatorListenerAdapter() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate.1
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                DropdownMenuEndIconDelegate.this.refreshIconState();
                DropdownMenuEndIconDelegate.this.fadeInAnim.start();
            }
        });
    }

    private ValueAnimator getAlphaAnimator(int duration, float... values) {
        ValueAnimator animator = ValueAnimator.ofFloat(values);
        animator.setInterpolator(this.animationFadeInterpolator);
        animator.setDuration(duration);
        animator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: com.google.android.material.textfield.DropdownMenuEndIconDelegate$$ExternalSyntheticLambda3
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                DropdownMenuEndIconDelegate.this.m131x6b943a83(valueAnimator);
            }
        });
        return animator;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$getAlphaAnimator$6$com-google-android-material-textfield-DropdownMenuEndIconDelegate  reason: not valid java name */
    public /* synthetic */ void m131x6b943a83(ValueAnimator animation) {
        float alpha = ((Float) animation.getAnimatedValue()).floatValue();
        this.endIconView.setAlpha(alpha);
    }
}
