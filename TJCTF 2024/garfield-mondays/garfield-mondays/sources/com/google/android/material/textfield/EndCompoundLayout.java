package com.google.android.material.textfield;

import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityManager;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.appcompat.widget.TintTypedArray;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.view.GravityCompat;
import androidx.core.view.MarginLayoutParamsCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityManagerCompat;
import androidx.core.widget.TextViewCompat;
import com.google.android.material.R;
import com.google.android.material.internal.CheckableImageButton;
import com.google.android.material.internal.TextWatcherAdapter;
import com.google.android.material.internal.ViewUtils;
import com.google.android.material.resources.MaterialResources;
import com.google.android.material.textfield.TextInputLayout;
import java.util.Iterator;
import java.util.LinkedHashSet;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class EndCompoundLayout extends LinearLayout {
    private final AccessibilityManager accessibilityManager;
    private EditText editText;
    private final TextWatcher editTextWatcher;
    private final LinkedHashSet<TextInputLayout.OnEndIconChangedListener> endIconChangedListeners;
    private final EndIconDelegates endIconDelegates;
    private final FrameLayout endIconFrame;
    private int endIconMinSize;
    private int endIconMode;
    private View.OnLongClickListener endIconOnLongClickListener;
    private ImageView.ScaleType endIconScaleType;
    private ColorStateList endIconTintList;
    private PorterDuff.Mode endIconTintMode;
    private final CheckableImageButton endIconView;
    private View.OnLongClickListener errorIconOnLongClickListener;
    private ColorStateList errorIconTintList;
    private PorterDuff.Mode errorIconTintMode;
    private final CheckableImageButton errorIconView;
    private boolean hintExpanded;
    private final TextInputLayout.OnEditTextAttachedListener onEditTextAttachedListener;
    private CharSequence suffixText;
    private final TextView suffixTextView;
    final TextInputLayout textInputLayout;
    private AccessibilityManagerCompat.TouchExplorationStateChangeListener touchExplorationStateChangeListener;

    /* JADX INFO: Access modifiers changed from: package-private */
    public EndCompoundLayout(TextInputLayout textInputLayout, TintTypedArray a) {
        super(textInputLayout.getContext());
        this.endIconMode = 0;
        this.endIconChangedListeners = new LinkedHashSet<>();
        this.editTextWatcher = new TextWatcherAdapter() { // from class: com.google.android.material.textfield.EndCompoundLayout.1
            @Override // com.google.android.material.internal.TextWatcherAdapter, android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                EndCompoundLayout.this.getEndIconDelegate().beforeEditTextChanged(s, start, count, after);
            }

            @Override // com.google.android.material.internal.TextWatcherAdapter, android.text.TextWatcher
            public void afterTextChanged(Editable s) {
                EndCompoundLayout.this.getEndIconDelegate().afterEditTextChanged(s);
            }
        };
        this.onEditTextAttachedListener = new TextInputLayout.OnEditTextAttachedListener() { // from class: com.google.android.material.textfield.EndCompoundLayout.2
            @Override // com.google.android.material.textfield.TextInputLayout.OnEditTextAttachedListener
            public void onEditTextAttached(TextInputLayout textInputLayout2) {
                if (EndCompoundLayout.this.editText != textInputLayout2.getEditText()) {
                    if (EndCompoundLayout.this.editText != null) {
                        EndCompoundLayout.this.editText.removeTextChangedListener(EndCompoundLayout.this.editTextWatcher);
                        if (EndCompoundLayout.this.editText.getOnFocusChangeListener() == EndCompoundLayout.this.getEndIconDelegate().getOnEditTextFocusChangeListener()) {
                            EndCompoundLayout.this.editText.setOnFocusChangeListener(null);
                        }
                    }
                    EndCompoundLayout.this.editText = textInputLayout2.getEditText();
                    if (EndCompoundLayout.this.editText != null) {
                        EndCompoundLayout.this.editText.addTextChangedListener(EndCompoundLayout.this.editTextWatcher);
                    }
                    EndCompoundLayout.this.getEndIconDelegate().onEditTextAttached(EndCompoundLayout.this.editText);
                    EndCompoundLayout.this.setOnFocusChangeListenersIfNeeded(EndCompoundLayout.this.getEndIconDelegate());
                }
            }
        };
        this.accessibilityManager = (AccessibilityManager) getContext().getSystemService("accessibility");
        this.textInputLayout = textInputLayout;
        setVisibility(8);
        setOrientation(0);
        setLayoutParams(new FrameLayout.LayoutParams(-2, -1, GravityCompat.END));
        this.endIconFrame = new FrameLayout(getContext());
        this.endIconFrame.setVisibility(8);
        this.endIconFrame.setLayoutParams(new LinearLayout.LayoutParams(-2, -1));
        LayoutInflater layoutInflater = LayoutInflater.from(getContext());
        this.errorIconView = createIconView(this, layoutInflater, R.id.text_input_error_icon);
        this.endIconView = createIconView(this.endIconFrame, layoutInflater, R.id.text_input_end_icon);
        this.endIconDelegates = new EndIconDelegates(this, a);
        this.suffixTextView = new AppCompatTextView(getContext());
        initErrorIconView(a);
        initEndIconView(a);
        initSuffixTextView(a);
        this.endIconFrame.addView(this.endIconView);
        addView(this.suffixTextView);
        addView(this.endIconFrame);
        addView(this.errorIconView);
        textInputLayout.addOnEditTextAttachedListener(this.onEditTextAttachedListener);
        addOnAttachStateChangeListener(new View.OnAttachStateChangeListener() { // from class: com.google.android.material.textfield.EndCompoundLayout.3
            @Override // android.view.View.OnAttachStateChangeListener
            public void onViewAttachedToWindow(View ignored) {
                EndCompoundLayout.this.addTouchExplorationStateChangeListenerIfNeeded();
            }

            @Override // android.view.View.OnAttachStateChangeListener
            public void onViewDetachedFromWindow(View ignored) {
                EndCompoundLayout.this.removeTouchExplorationStateChangeListenerIfNeeded();
            }
        });
    }

    private CheckableImageButton createIconView(ViewGroup root, LayoutInflater inflater, int id) {
        CheckableImageButton iconView = (CheckableImageButton) inflater.inflate(R.layout.design_text_input_end_icon, root, false);
        iconView.setId(id);
        IconHelper.setCompatRippleBackgroundIfNeeded(iconView);
        if (MaterialResources.isFontScaleAtLeast1_3(getContext())) {
            ViewGroup.MarginLayoutParams lp = (ViewGroup.MarginLayoutParams) iconView.getLayoutParams();
            MarginLayoutParamsCompat.setMarginStart(lp, 0);
        }
        return iconView;
    }

    private void initErrorIconView(TintTypedArray a) {
        if (a.hasValue(R.styleable.TextInputLayout_errorIconTint)) {
            this.errorIconTintList = MaterialResources.getColorStateList(getContext(), a, R.styleable.TextInputLayout_errorIconTint);
        }
        if (a.hasValue(R.styleable.TextInputLayout_errorIconTintMode)) {
            this.errorIconTintMode = ViewUtils.parseTintMode(a.getInt(R.styleable.TextInputLayout_errorIconTintMode, -1), null);
        }
        if (a.hasValue(R.styleable.TextInputLayout_errorIconDrawable)) {
            setErrorIconDrawable(a.getDrawable(R.styleable.TextInputLayout_errorIconDrawable));
        }
        this.errorIconView.setContentDescription(getResources().getText(R.string.error_icon_content_description));
        ViewCompat.setImportantForAccessibility(this.errorIconView, 2);
        this.errorIconView.setClickable(false);
        this.errorIconView.setPressable(false);
        this.errorIconView.setFocusable(false);
    }

    private void initEndIconView(TintTypedArray a) {
        if (!a.hasValue(R.styleable.TextInputLayout_passwordToggleEnabled)) {
            if (a.hasValue(R.styleable.TextInputLayout_endIconTint)) {
                this.endIconTintList = MaterialResources.getColorStateList(getContext(), a, R.styleable.TextInputLayout_endIconTint);
            }
            if (a.hasValue(R.styleable.TextInputLayout_endIconTintMode)) {
                this.endIconTintMode = ViewUtils.parseTintMode(a.getInt(R.styleable.TextInputLayout_endIconTintMode, -1), null);
            }
        }
        if (a.hasValue(R.styleable.TextInputLayout_endIconMode)) {
            setEndIconMode(a.getInt(R.styleable.TextInputLayout_endIconMode, 0));
            if (a.hasValue(R.styleable.TextInputLayout_endIconContentDescription)) {
                setEndIconContentDescription(a.getText(R.styleable.TextInputLayout_endIconContentDescription));
            }
            setEndIconCheckable(a.getBoolean(R.styleable.TextInputLayout_endIconCheckable, true));
        } else if (a.hasValue(R.styleable.TextInputLayout_passwordToggleEnabled)) {
            if (a.hasValue(R.styleable.TextInputLayout_passwordToggleTint)) {
                this.endIconTintList = MaterialResources.getColorStateList(getContext(), a, R.styleable.TextInputLayout_passwordToggleTint);
            }
            if (a.hasValue(R.styleable.TextInputLayout_passwordToggleTintMode)) {
                this.endIconTintMode = ViewUtils.parseTintMode(a.getInt(R.styleable.TextInputLayout_passwordToggleTintMode, -1), null);
            }
            setEndIconMode(a.getBoolean(R.styleable.TextInputLayout_passwordToggleEnabled, false) ? 1 : 0);
            setEndIconContentDescription(a.getText(R.styleable.TextInputLayout_passwordToggleContentDescription));
        }
        setEndIconMinSize(a.getDimensionPixelSize(R.styleable.TextInputLayout_endIconMinSize, getResources().getDimensionPixelSize(R.dimen.mtrl_min_touch_target_size)));
        if (a.hasValue(R.styleable.TextInputLayout_endIconScaleType)) {
            setEndIconScaleType(IconHelper.convertScaleType(a.getInt(R.styleable.TextInputLayout_endIconScaleType, -1)));
        }
    }

    private void initSuffixTextView(TintTypedArray a) {
        this.suffixTextView.setVisibility(8);
        this.suffixTextView.setId(R.id.textinput_suffix_text);
        this.suffixTextView.setLayoutParams(new LinearLayout.LayoutParams(-2, -2, 80.0f));
        ViewCompat.setAccessibilityLiveRegion(this.suffixTextView, 1);
        setSuffixTextAppearance(a.getResourceId(R.styleable.TextInputLayout_suffixTextAppearance, 0));
        if (a.hasValue(R.styleable.TextInputLayout_suffixTextColor)) {
            setSuffixTextColor(a.getColorStateList(R.styleable.TextInputLayout_suffixTextColor));
        }
        setSuffixText(a.getText(R.styleable.TextInputLayout_suffixText));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setErrorIconDrawable(int resId) {
        setErrorIconDrawable(resId != 0 ? AppCompatResources.getDrawable(getContext(), resId) : null);
        refreshErrorIconDrawableState();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setErrorIconDrawable(Drawable errorIconDrawable) {
        this.errorIconView.setImageDrawable(errorIconDrawable);
        updateErrorIconVisibility();
        IconHelper.applyIconTint(this.textInputLayout, this.errorIconView, this.errorIconTintList, this.errorIconTintMode);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Drawable getErrorIconDrawable() {
        return this.errorIconView.getDrawable();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setErrorIconTintList(ColorStateList errorIconTintList) {
        if (this.errorIconTintList != errorIconTintList) {
            this.errorIconTintList = errorIconTintList;
            IconHelper.applyIconTint(this.textInputLayout, this.errorIconView, errorIconTintList, this.errorIconTintMode);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setErrorIconTintMode(PorterDuff.Mode errorIconTintMode) {
        if (this.errorIconTintMode != errorIconTintMode) {
            this.errorIconTintMode = errorIconTintMode;
            IconHelper.applyIconTint(this.textInputLayout, this.errorIconView, this.errorIconTintList, this.errorIconTintMode);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setErrorIconOnClickListener(View.OnClickListener errorIconOnClickListener) {
        IconHelper.setIconOnClickListener(this.errorIconView, errorIconOnClickListener, this.errorIconOnLongClickListener);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CheckableImageButton getEndIconView() {
        return this.endIconView;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public EndIconDelegate getEndIconDelegate() {
        return this.endIconDelegates.get(this.endIconMode);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getEndIconMode() {
        return this.endIconMode;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setEndIconMode(int endIconMode) {
        if (this.endIconMode == endIconMode) {
            return;
        }
        tearDownDelegate(getEndIconDelegate());
        int previousEndIconMode = this.endIconMode;
        this.endIconMode = endIconMode;
        dispatchOnEndIconChanged(previousEndIconMode);
        setEndIconVisible(endIconMode != 0);
        EndIconDelegate delegate = getEndIconDelegate();
        setEndIconDrawable(getIconResId(delegate));
        setEndIconContentDescription(delegate.getIconContentDescriptionResId());
        setEndIconCheckable(delegate.isIconCheckable());
        if (delegate.isBoxBackgroundModeSupported(this.textInputLayout.getBoxBackgroundMode())) {
            setUpDelegate(delegate);
            setEndIconOnClickListener(delegate.getOnIconClickListener());
            if (this.editText != null) {
                delegate.onEditTextAttached(this.editText);
                setOnFocusChangeListenersIfNeeded(delegate);
            }
            IconHelper.applyIconTint(this.textInputLayout, this.endIconView, this.endIconTintList, this.endIconTintMode);
            refreshIconState(true);
            return;
        }
        throw new IllegalStateException("The current box background mode " + this.textInputLayout.getBoxBackgroundMode() + " is not supported by the end icon mode " + endIconMode);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void refreshIconState(boolean force) {
        boolean wasActivated;
        boolean wasChecked;
        boolean stateChanged = false;
        EndIconDelegate delegate = getEndIconDelegate();
        if (delegate.isIconCheckable() && (wasChecked = this.endIconView.isChecked()) != delegate.isIconChecked()) {
            this.endIconView.setChecked(!wasChecked);
            stateChanged = true;
        }
        if (delegate.isIconActivable() && (wasActivated = this.endIconView.isActivated()) != delegate.isIconActivated()) {
            setEndIconActivated(!wasActivated);
            stateChanged = true;
        }
        if (force || stateChanged) {
            refreshEndIconDrawableState();
        }
    }

    private void setUpDelegate(EndIconDelegate delegate) {
        delegate.setUp();
        this.touchExplorationStateChangeListener = delegate.getTouchExplorationStateChangeListener();
        addTouchExplorationStateChangeListenerIfNeeded();
    }

    private void tearDownDelegate(EndIconDelegate delegate) {
        removeTouchExplorationStateChangeListenerIfNeeded();
        this.touchExplorationStateChangeListener = null;
        delegate.tearDown();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void addTouchExplorationStateChangeListenerIfNeeded() {
        if (this.touchExplorationStateChangeListener != null && this.accessibilityManager != null && ViewCompat.isAttachedToWindow(this)) {
            AccessibilityManagerCompat.addTouchExplorationStateChangeListener(this.accessibilityManager, this.touchExplorationStateChangeListener);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void removeTouchExplorationStateChangeListenerIfNeeded() {
        if (this.touchExplorationStateChangeListener != null && this.accessibilityManager != null) {
            AccessibilityManagerCompat.removeTouchExplorationStateChangeListener(this.accessibilityManager, this.touchExplorationStateChangeListener);
        }
    }

    private int getIconResId(EndIconDelegate delegate) {
        int customIconResId = this.endIconDelegates.customEndIconDrawableId;
        return customIconResId == 0 ? delegate.getIconDrawableResId() : customIconResId;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setEndIconOnClickListener(View.OnClickListener endIconOnClickListener) {
        IconHelper.setIconOnClickListener(this.endIconView, endIconOnClickListener, this.endIconOnLongClickListener);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setEndIconOnLongClickListener(View.OnLongClickListener endIconOnLongClickListener) {
        this.endIconOnLongClickListener = endIconOnLongClickListener;
        IconHelper.setIconOnLongClickListener(this.endIconView, endIconOnLongClickListener);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setErrorIconOnLongClickListener(View.OnLongClickListener errorIconOnLongClickListener) {
        this.errorIconOnLongClickListener = errorIconOnLongClickListener;
        IconHelper.setIconOnLongClickListener(this.errorIconView, errorIconOnLongClickListener);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setOnFocusChangeListenersIfNeeded(EndIconDelegate delegate) {
        if (this.editText == null) {
            return;
        }
        if (delegate.getOnEditTextFocusChangeListener() != null) {
            this.editText.setOnFocusChangeListener(delegate.getOnEditTextFocusChangeListener());
        }
        if (delegate.getOnIconViewFocusChangeListener() != null) {
            this.endIconView.setOnFocusChangeListener(delegate.getOnIconViewFocusChangeListener());
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void refreshErrorIconDrawableState() {
        IconHelper.refreshIconDrawableState(this.textInputLayout, this.errorIconView, this.errorIconTintList);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setEndIconVisible(boolean visible) {
        if (isEndIconVisible() != visible) {
            this.endIconView.setVisibility(visible ? 0 : 8);
            updateEndLayoutVisibility();
            updateSuffixTextViewPadding();
            this.textInputLayout.updateDummyDrawables();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isEndIconVisible() {
        return this.endIconFrame.getVisibility() == 0 && this.endIconView.getVisibility() == 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setEndIconActivated(boolean endIconActivated) {
        this.endIconView.setActivated(endIconActivated);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void refreshEndIconDrawableState() {
        IconHelper.refreshIconDrawableState(this.textInputLayout, this.endIconView, this.endIconTintList);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setEndIconCheckable(boolean endIconCheckable) {
        this.endIconView.setCheckable(endIconCheckable);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isEndIconCheckable() {
        return this.endIconView.isCheckable();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isEndIconChecked() {
        return hasEndIcon() && this.endIconView.isChecked();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void checkEndIcon() {
        this.endIconView.performClick();
        this.endIconView.jumpDrawablesToCurrentState();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setEndIconDrawable(int resId) {
        setEndIconDrawable(resId != 0 ? AppCompatResources.getDrawable(getContext(), resId) : null);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setEndIconDrawable(Drawable endIconDrawable) {
        this.endIconView.setImageDrawable(endIconDrawable);
        if (endIconDrawable != null) {
            IconHelper.applyIconTint(this.textInputLayout, this.endIconView, this.endIconTintList, this.endIconTintMode);
            refreshEndIconDrawableState();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Drawable getEndIconDrawable() {
        return this.endIconView.getDrawable();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setEndIconContentDescription(int resId) {
        setEndIconContentDescription(resId != 0 ? getResources().getText(resId) : null);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setEndIconContentDescription(CharSequence endIconContentDescription) {
        if (getEndIconContentDescription() != endIconContentDescription) {
            this.endIconView.setContentDescription(endIconContentDescription);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CharSequence getEndIconContentDescription() {
        return this.endIconView.getContentDescription();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setEndIconTintList(ColorStateList endIconTintList) {
        if (this.endIconTintList != endIconTintList) {
            this.endIconTintList = endIconTintList;
            IconHelper.applyIconTint(this.textInputLayout, this.endIconView, this.endIconTintList, this.endIconTintMode);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setEndIconTintMode(PorterDuff.Mode endIconTintMode) {
        if (this.endIconTintMode != endIconTintMode) {
            this.endIconTintMode = endIconTintMode;
            IconHelper.applyIconTint(this.textInputLayout, this.endIconView, this.endIconTintList, this.endIconTintMode);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setEndIconMinSize(int iconSize) {
        if (iconSize < 0) {
            throw new IllegalArgumentException("endIconSize cannot be less than 0");
        }
        if (iconSize != this.endIconMinSize) {
            this.endIconMinSize = iconSize;
            IconHelper.setIconMinSize(this.endIconView, iconSize);
            IconHelper.setIconMinSize(this.errorIconView, iconSize);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getEndIconMinSize() {
        return this.endIconMinSize;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setEndIconScaleType(ImageView.ScaleType endIconScaleType) {
        this.endIconScaleType = endIconScaleType;
        IconHelper.setIconScaleType(this.endIconView, endIconScaleType);
        IconHelper.setIconScaleType(this.errorIconView, endIconScaleType);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ImageView.ScaleType getEndIconScaleType() {
        return this.endIconScaleType;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void addOnEndIconChangedListener(TextInputLayout.OnEndIconChangedListener listener) {
        this.endIconChangedListeners.add(listener);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void removeOnEndIconChangedListener(TextInputLayout.OnEndIconChangedListener listener) {
        this.endIconChangedListeners.remove(listener);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void clearOnEndIconChangedListeners() {
        this.endIconChangedListeners.clear();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean hasEndIcon() {
        return this.endIconMode != 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public TextView getSuffixTextView() {
        return this.suffixTextView;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setSuffixText(CharSequence suffixText) {
        this.suffixText = TextUtils.isEmpty(suffixText) ? null : suffixText;
        this.suffixTextView.setText(suffixText);
        updateSuffixTextVisibility();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CharSequence getSuffixText() {
        return this.suffixText;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setSuffixTextAppearance(int suffixTextAppearance) {
        TextViewCompat.setTextAppearance(this.suffixTextView, suffixTextAppearance);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setSuffixTextColor(ColorStateList suffixTextColor) {
        this.suffixTextView.setTextColor(suffixTextColor);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ColorStateList getSuffixTextColor() {
        return this.suffixTextView.getTextColors();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setPasswordVisibilityToggleDrawable(int resId) {
        setPasswordVisibilityToggleDrawable(resId != 0 ? AppCompatResources.getDrawable(getContext(), resId) : null);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setPasswordVisibilityToggleDrawable(Drawable icon) {
        this.endIconView.setImageDrawable(icon);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setPasswordVisibilityToggleContentDescription(int resId) {
        setPasswordVisibilityToggleContentDescription(resId != 0 ? getResources().getText(resId) : null);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setPasswordVisibilityToggleContentDescription(CharSequence description) {
        this.endIconView.setContentDescription(description);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Drawable getPasswordVisibilityToggleDrawable() {
        return this.endIconView.getDrawable();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CharSequence getPasswordVisibilityToggleContentDescription() {
        return this.endIconView.getContentDescription();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isPasswordVisibilityToggleEnabled() {
        return this.endIconMode == 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setPasswordVisibilityToggleEnabled(boolean enabled) {
        if (enabled && this.endIconMode != 1) {
            setEndIconMode(1);
        } else if (!enabled) {
            setEndIconMode(0);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setPasswordVisibilityToggleTintList(ColorStateList tintList) {
        this.endIconTintList = tintList;
        IconHelper.applyIconTint(this.textInputLayout, this.endIconView, this.endIconTintList, this.endIconTintMode);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setPasswordVisibilityToggleTintMode(PorterDuff.Mode mode) {
        this.endIconTintMode = mode;
        IconHelper.applyIconTint(this.textInputLayout, this.endIconView, this.endIconTintList, this.endIconTintMode);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void togglePasswordVisibilityToggle(boolean shouldSkipAnimations) {
        if (this.endIconMode == 1) {
            this.endIconView.performClick();
            if (shouldSkipAnimations) {
                this.endIconView.jumpDrawablesToCurrentState();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void onHintStateChanged(boolean hintExpanded) {
        this.hintExpanded = hintExpanded;
        updateSuffixTextVisibility();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void onTextInputBoxStateUpdated() {
        updateErrorIconVisibility();
        refreshErrorIconDrawableState();
        refreshEndIconDrawableState();
        if (getEndIconDelegate().shouldTintIconOnError()) {
            tintEndIconOnError(this.textInputLayout.shouldShowError());
        }
    }

    private void updateSuffixTextVisibility() {
        int oldVisibility = this.suffixTextView.getVisibility();
        int newVisibility = (this.suffixText == null || this.hintExpanded) ? 8 : 0;
        if (oldVisibility != newVisibility) {
            getEndIconDelegate().onSuffixVisibilityChanged(newVisibility == 0);
        }
        updateEndLayoutVisibility();
        this.suffixTextView.setVisibility(newVisibility);
        this.textInputLayout.updateDummyDrawables();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void updateSuffixTextViewPadding() {
        if (this.textInputLayout.editText == null) {
            return;
        }
        int endPadding = (isEndIconVisible() || isErrorIconVisible()) ? 0 : ViewCompat.getPaddingEnd(this.textInputLayout.editText);
        ViewCompat.setPaddingRelative(this.suffixTextView, getContext().getResources().getDimensionPixelSize(R.dimen.material_input_text_to_prefix_suffix_padding), this.textInputLayout.editText.getPaddingTop(), endPadding, this.textInputLayout.editText.getPaddingBottom());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getSuffixTextEndOffset() {
        int endIconOffset;
        if (isEndIconVisible() || isErrorIconVisible()) {
            endIconOffset = this.endIconView.getMeasuredWidth() + MarginLayoutParamsCompat.getMarginStart((ViewGroup.MarginLayoutParams) this.endIconView.getLayoutParams());
        } else {
            endIconOffset = 0;
        }
        return ViewCompat.getPaddingEnd(this) + ViewCompat.getPaddingEnd(this.suffixTextView) + endIconOffset;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CheckableImageButton getCurrentEndIconView() {
        if (isErrorIconVisible()) {
            return this.errorIconView;
        }
        if (hasEndIcon() && isEndIconVisible()) {
            return this.endIconView;
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isErrorIconVisible() {
        return this.errorIconView.getVisibility() == 0;
    }

    private void updateErrorIconVisibility() {
        boolean visible = getErrorIconDrawable() != null && this.textInputLayout.isErrorEnabled() && this.textInputLayout.shouldShowError();
        this.errorIconView.setVisibility(visible ? 0 : 8);
        updateEndLayoutVisibility();
        updateSuffixTextViewPadding();
        if (!hasEndIcon()) {
            this.textInputLayout.updateDummyDrawables();
        }
    }

    private void updateEndLayoutVisibility() {
        this.endIconFrame.setVisibility((this.endIconView.getVisibility() != 0 || isErrorIconVisible()) ? 8 : 0);
        int suffixTextVisibility = (this.suffixText == null || this.hintExpanded) ? 8 : 0;
        boolean shouldBeVisible = isEndIconVisible() || isErrorIconVisible() || suffixTextVisibility == 0;
        setVisibility(shouldBeVisible ? 0 : 8);
    }

    private void dispatchOnEndIconChanged(int previousIcon) {
        Iterator<TextInputLayout.OnEndIconChangedListener> it = this.endIconChangedListeners.iterator();
        while (it.hasNext()) {
            TextInputLayout.OnEndIconChangedListener listener = it.next();
            listener.onEndIconChanged(this.textInputLayout, previousIcon);
        }
    }

    private void tintEndIconOnError(boolean tintEndIconOnError) {
        if (tintEndIconOnError && getEndIconDrawable() != null) {
            Drawable endIconDrawable = DrawableCompat.wrap(getEndIconDrawable()).mutate();
            DrawableCompat.setTint(endIconDrawable, this.textInputLayout.getErrorCurrentTextColors());
            this.endIconView.setImageDrawable(endIconDrawable);
            return;
        }
        IconHelper.applyIconTint(this.textInputLayout, this.endIconView, this.endIconTintList, this.endIconTintMode);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class EndIconDelegates {
        private final int customEndIconDrawableId;
        private final SparseArray<EndIconDelegate> delegates = new SparseArray<>();
        private final EndCompoundLayout endLayout;
        private final int passwordIconDrawableId;

        EndIconDelegates(EndCompoundLayout endLayout, TintTypedArray a) {
            this.endLayout = endLayout;
            this.customEndIconDrawableId = a.getResourceId(R.styleable.TextInputLayout_endIconDrawable, 0);
            this.passwordIconDrawableId = a.getResourceId(R.styleable.TextInputLayout_passwordToggleDrawable, 0);
        }

        EndIconDelegate get(int endIconMode) {
            EndIconDelegate delegate = this.delegates.get(endIconMode);
            if (delegate == null) {
                EndIconDelegate delegate2 = create(endIconMode);
                this.delegates.append(endIconMode, delegate2);
                return delegate2;
            }
            return delegate;
        }

        private EndIconDelegate create(int endIconMode) {
            switch (endIconMode) {
                case -1:
                    return new CustomEndIconDelegate(this.endLayout);
                case 0:
                    return new NoEndIconDelegate(this.endLayout);
                case 1:
                    return new PasswordToggleEndIconDelegate(this.endLayout, this.passwordIconDrawableId);
                case 2:
                    return new ClearTextEndIconDelegate(this.endLayout);
                case 3:
                    return new DropdownMenuEndIconDelegate(this.endLayout);
                default:
                    throw new IllegalArgumentException("Invalid end icon mode: " + endIconMode);
            }
        }
    }
}
