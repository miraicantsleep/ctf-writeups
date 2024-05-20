package com.google.android.material.navigation;

import android.animation.Animator;
import android.animation.ValueAnimator;
import android.app.Activity;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.InsetDrawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.Pair;
import android.util.TypedValue;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.ViewTreeObserver;
import androidx.activity.BackEventCompat;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.appcompat.view.SupportMenuInflater;
import androidx.appcompat.view.menu.MenuBuilder;
import androidx.appcompat.view.menu.MenuItemImpl;
import androidx.appcompat.widget.TintTypedArray;
import androidx.constraintlayout.core.widgets.analyzer.BasicMeasure;
import androidx.core.content.ContextCompat;
import androidx.core.view.GravityCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.customview.view.AbsSavedState;
import androidx.drawerlayout.widget.DrawerLayout;
import com.google.android.material.R;
import com.google.android.material.canvas.CanvasCompat;
import com.google.android.material.drawable.DrawableUtils;
import com.google.android.material.internal.ContextUtils;
import com.google.android.material.internal.NavigationMenu;
import com.google.android.material.internal.NavigationMenuPresenter;
import com.google.android.material.internal.ScrimInsetsFrameLayout;
import com.google.android.material.internal.ThemeEnforcement;
import com.google.android.material.internal.WindowUtils;
import com.google.android.material.motion.MaterialBackHandler;
import com.google.android.material.motion.MaterialBackOrchestrator;
import com.google.android.material.motion.MaterialSideContainerBackHelper;
import com.google.android.material.resources.MaterialResources;
import com.google.android.material.ripple.RippleUtils;
import com.google.android.material.shape.MaterialShapeDrawable;
import com.google.android.material.shape.MaterialShapeUtils;
import com.google.android.material.shape.ShapeAppearanceModel;
import com.google.android.material.shape.ShapeableDelegate;
import com.google.android.material.theme.overlay.MaterialThemeOverlay;
import java.util.Objects;
/* loaded from: classes.dex */
public class NavigationView extends ScrimInsetsFrameLayout implements MaterialBackHandler {
    private static final int PRESENTER_NAVIGATION_VIEW_ID = 1;
    private final DrawerLayout.DrawerListener backDrawerListener;
    private final MaterialBackOrchestrator backOrchestrator;
    private boolean bottomInsetScrimEnabled;
    private int drawerLayoutCornerSize;
    OnNavigationItemSelectedListener listener;
    private final int maxWidth;
    private final NavigationMenu menu;
    private MenuInflater menuInflater;
    private ViewTreeObserver.OnGlobalLayoutListener onGlobalLayoutListener;
    private final NavigationMenuPresenter presenter;
    private final ShapeableDelegate shapeableDelegate;
    private final MaterialSideContainerBackHelper sideContainerBackHelper;
    private final int[] tmpLocation;
    private boolean topInsetScrimEnabled;
    private static final int[] CHECKED_STATE_SET = {16842912};
    private static final int[] DISABLED_STATE_SET = {-16842910};
    private static final int DEF_STYLE_RES = R.style.Widget_Design_NavigationView;

    /* loaded from: classes.dex */
    public interface OnNavigationItemSelectedListener {
        boolean onNavigationItemSelected(MenuItem menuItem);
    }

    public NavigationView(Context context) {
        this(context, null);
    }

    public NavigationView(Context context, AttributeSet attrs) {
        this(context, attrs, R.attr.navigationViewStyle);
    }

    public NavigationView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(MaterialThemeOverlay.wrap(context, attrs, defStyleAttr, DEF_STYLE_RES), attrs, defStyleAttr);
        ColorStateList itemIconTint;
        int i;
        int i2;
        this.presenter = new NavigationMenuPresenter();
        this.tmpLocation = new int[2];
        this.topInsetScrimEnabled = true;
        this.bottomInsetScrimEnabled = true;
        this.drawerLayoutCornerSize = 0;
        this.shapeableDelegate = ShapeableDelegate.create(this);
        this.sideContainerBackHelper = new MaterialSideContainerBackHelper(this);
        this.backOrchestrator = new MaterialBackOrchestrator(this);
        this.backDrawerListener = new DrawerLayout.SimpleDrawerListener() { // from class: com.google.android.material.navigation.NavigationView.1
            @Override // androidx.drawerlayout.widget.DrawerLayout.SimpleDrawerListener, androidx.drawerlayout.widget.DrawerLayout.DrawerListener
            public void onDrawerOpened(View drawerView) {
                if (drawerView == NavigationView.this) {
                    final MaterialBackOrchestrator materialBackOrchestrator = NavigationView.this.backOrchestrator;
                    Objects.requireNonNull(materialBackOrchestrator);
                    drawerView.post(new Runnable() { // from class: com.google.android.material.navigation.NavigationView$1$$ExternalSyntheticLambda0
                        @Override // java.lang.Runnable
                        public final void run() {
                            MaterialBackOrchestrator.this.startListeningForBackCallbacksWithPriorityOverlay();
                        }
                    });
                }
            }

            @Override // androidx.drawerlayout.widget.DrawerLayout.SimpleDrawerListener, androidx.drawerlayout.widget.DrawerLayout.DrawerListener
            public void onDrawerClosed(View drawerView) {
                if (drawerView == NavigationView.this) {
                    NavigationView.this.backOrchestrator.stopListeningForBackCallbacks();
                }
            }
        };
        Context context2 = getContext();
        this.menu = new NavigationMenu(context2);
        TintTypedArray a = ThemeEnforcement.obtainTintedStyledAttributes(context2, attrs, R.styleable.NavigationView, defStyleAttr, DEF_STYLE_RES, new int[0]);
        if (a.hasValue(R.styleable.NavigationView_android_background)) {
            ViewCompat.setBackground(this, a.getDrawable(R.styleable.NavigationView_android_background));
        }
        this.drawerLayoutCornerSize = a.getDimensionPixelSize(R.styleable.NavigationView_drawerLayoutCornerSize, 0);
        Drawable background = getBackground();
        ColorStateList backgroundColorStateList = DrawableUtils.getColorStateListOrNull(background);
        if (background == null || backgroundColorStateList != null) {
            ShapeAppearanceModel shapeAppearanceModel = ShapeAppearanceModel.builder(context2, attrs, defStyleAttr, DEF_STYLE_RES).build();
            MaterialShapeDrawable materialShapeDrawable = new MaterialShapeDrawable(shapeAppearanceModel);
            if (backgroundColorStateList != null) {
                materialShapeDrawable.setFillColor(backgroundColorStateList);
            }
            materialShapeDrawable.initializeElevationOverlay(context2);
            ViewCompat.setBackground(this, materialShapeDrawable);
        }
        if (a.hasValue(R.styleable.NavigationView_elevation)) {
            setElevation(a.getDimensionPixelSize(R.styleable.NavigationView_elevation, 0));
        }
        setFitsSystemWindows(a.getBoolean(R.styleable.NavigationView_android_fitsSystemWindows, false));
        this.maxWidth = a.getDimensionPixelSize(R.styleable.NavigationView_android_maxWidth, 0);
        ColorStateList subheaderColor = a.hasValue(R.styleable.NavigationView_subheaderColor) ? a.getColorStateList(R.styleable.NavigationView_subheaderColor) : null;
        int subheaderTextAppearance = a.hasValue(R.styleable.NavigationView_subheaderTextAppearance) ? a.getResourceId(R.styleable.NavigationView_subheaderTextAppearance, 0) : 0;
        if (subheaderTextAppearance == 0 && subheaderColor == null) {
            subheaderColor = createDefaultColorStateList(16842808);
        }
        if (a.hasValue(R.styleable.NavigationView_itemIconTint)) {
            itemIconTint = a.getColorStateList(R.styleable.NavigationView_itemIconTint);
        } else {
            itemIconTint = createDefaultColorStateList(16842808);
        }
        int textAppearance = a.hasValue(R.styleable.NavigationView_itemTextAppearance) ? a.getResourceId(R.styleable.NavigationView_itemTextAppearance, 0) : 0;
        boolean textAppearanceActiveBoldEnabled = a.getBoolean(R.styleable.NavigationView_itemTextAppearanceActiveBoldEnabled, true);
        if (a.hasValue(R.styleable.NavigationView_itemIconSize)) {
            setItemIconSize(a.getDimensionPixelSize(R.styleable.NavigationView_itemIconSize, 0));
        }
        ColorStateList itemTextColor = a.hasValue(R.styleable.NavigationView_itemTextColor) ? a.getColorStateList(R.styleable.NavigationView_itemTextColor) : null;
        if (textAppearance == 0 && itemTextColor == null) {
            itemTextColor = createDefaultColorStateList(16842806);
        }
        Drawable itemBackground = a.getDrawable(R.styleable.NavigationView_itemBackground);
        if (itemBackground == null && hasShapeAppearance(a)) {
            itemBackground = createDefaultItemBackground(a);
            ColorStateList itemRippleColor = MaterialResources.getColorStateList(context2, a, R.styleable.NavigationView_itemRippleColor);
            if (itemRippleColor != null) {
                Drawable itemRippleMask = createDefaultItemDrawable(a, null);
                RippleDrawable ripple = new RippleDrawable(RippleUtils.sanitizeRippleDrawableColor(itemRippleColor), null, itemRippleMask);
                this.presenter.setItemForeground(ripple);
            }
        }
        if (a.hasValue(R.styleable.NavigationView_itemHorizontalPadding)) {
            int itemHorizontalPadding = a.getDimensionPixelSize(R.styleable.NavigationView_itemHorizontalPadding, 0);
            setItemHorizontalPadding(itemHorizontalPadding);
        }
        int itemHorizontalPadding2 = R.styleable.NavigationView_itemVerticalPadding;
        if (!a.hasValue(itemHorizontalPadding2)) {
            i = 0;
        } else {
            i = 0;
            int itemVerticalPadding = a.getDimensionPixelSize(R.styleable.NavigationView_itemVerticalPadding, 0);
            setItemVerticalPadding(itemVerticalPadding);
        }
        int dividerInsetStart = a.getDimensionPixelSize(R.styleable.NavigationView_dividerInsetStart, i);
        setDividerInsetStart(dividerInsetStart);
        int dividerInsetEnd = a.getDimensionPixelSize(R.styleable.NavigationView_dividerInsetEnd, i);
        setDividerInsetEnd(dividerInsetEnd);
        int subheaderInsetStart = a.getDimensionPixelSize(R.styleable.NavigationView_subheaderInsetStart, i);
        setSubheaderInsetStart(subheaderInsetStart);
        int subheaderInsetEnd = a.getDimensionPixelSize(R.styleable.NavigationView_subheaderInsetEnd, i);
        setSubheaderInsetEnd(subheaderInsetEnd);
        setTopInsetScrimEnabled(a.getBoolean(R.styleable.NavigationView_topInsetScrimEnabled, this.topInsetScrimEnabled));
        setBottomInsetScrimEnabled(a.getBoolean(R.styleable.NavigationView_bottomInsetScrimEnabled, this.bottomInsetScrimEnabled));
        int itemIconPadding = a.getDimensionPixelSize(R.styleable.NavigationView_itemIconPadding, 0);
        setItemMaxLines(a.getInt(R.styleable.NavigationView_itemMaxLines, 1));
        this.menu.setCallback(new MenuBuilder.Callback() { // from class: com.google.android.material.navigation.NavigationView.2
            @Override // androidx.appcompat.view.menu.MenuBuilder.Callback
            public boolean onMenuItemSelected(MenuBuilder menu, MenuItem item) {
                return NavigationView.this.listener != null && NavigationView.this.listener.onNavigationItemSelected(item);
            }

            @Override // androidx.appcompat.view.menu.MenuBuilder.Callback
            public void onMenuModeChange(MenuBuilder menu) {
            }
        });
        this.presenter.setId(1);
        this.presenter.initForMenu(context2, this.menu);
        if (subheaderTextAppearance != 0) {
            this.presenter.setSubheaderTextAppearance(subheaderTextAppearance);
        }
        this.presenter.setSubheaderColor(subheaderColor);
        this.presenter.setItemIconTintList(itemIconTint);
        this.presenter.setOverScrollMode(getOverScrollMode());
        if (textAppearance != 0) {
            this.presenter.setItemTextAppearance(textAppearance);
        }
        this.presenter.setItemTextAppearanceActiveBoldEnabled(textAppearanceActiveBoldEnabled);
        this.presenter.setItemTextColor(itemTextColor);
        this.presenter.setItemBackground(itemBackground);
        this.presenter.setItemIconPadding(itemIconPadding);
        this.menu.addMenuPresenter(this.presenter);
        addView((View) this.presenter.getMenuView(this));
        if (a.hasValue(R.styleable.NavigationView_menu)) {
            i2 = 0;
            inflateMenu(a.getResourceId(R.styleable.NavigationView_menu, 0));
        } else {
            i2 = 0;
        }
        if (a.hasValue(R.styleable.NavigationView_headerLayout)) {
            inflateHeaderView(a.getResourceId(R.styleable.NavigationView_headerLayout, i2));
        }
        a.recycle();
        setupInsetScrimsListener();
    }

    @Override // android.view.View
    public void setOverScrollMode(int overScrollMode) {
        super.setOverScrollMode(overScrollMode);
        if (this.presenter != null) {
            this.presenter.setOverScrollMode(overScrollMode);
        }
    }

    public void setForceCompatClippingEnabled(boolean enabled) {
        this.shapeableDelegate.setForceCompatClippingEnabled(this, enabled);
    }

    private void maybeUpdateCornerSizeForDrawerLayout(int width, int height) {
        if ((getParent() instanceof DrawerLayout) && (getLayoutParams() instanceof DrawerLayout.LayoutParams) && this.drawerLayoutCornerSize > 0 && (getBackground() instanceof MaterialShapeDrawable)) {
            int layoutGravity = ((DrawerLayout.LayoutParams) getLayoutParams()).gravity;
            boolean isAbsGravityLeft = GravityCompat.getAbsoluteGravity(layoutGravity, ViewCompat.getLayoutDirection(this)) == 3;
            MaterialShapeDrawable background = (MaterialShapeDrawable) getBackground();
            ShapeAppearanceModel.Builder builder = background.getShapeAppearanceModel().toBuilder().setAllCornerSizes(this.drawerLayoutCornerSize);
            if (isAbsGravityLeft) {
                builder.setTopLeftCornerSize(0.0f);
                builder.setBottomLeftCornerSize(0.0f);
            } else {
                builder.setTopRightCornerSize(0.0f);
                builder.setBottomRightCornerSize(0.0f);
            }
            ShapeAppearanceModel model = builder.build();
            background.setShapeAppearanceModel(model);
            this.shapeableDelegate.onShapeAppearanceChanged(this, model);
            this.shapeableDelegate.onMaskChanged(this, new RectF(0.0f, 0.0f, width, height));
            this.shapeableDelegate.setOffsetZeroCornerEdgeBoundsEnabled(this, true);
        }
    }

    private boolean hasShapeAppearance(TintTypedArray a) {
        return a.hasValue(R.styleable.NavigationView_itemShapeAppearance) || a.hasValue(R.styleable.NavigationView_itemShapeAppearanceOverlay);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.material.internal.ScrimInsetsFrameLayout, android.view.ViewGroup, android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        MaterialShapeUtils.setParentAbsoluteElevation(this);
        ViewParent parent = getParent();
        if ((parent instanceof DrawerLayout) && this.backOrchestrator.shouldListenForBackCallbacks()) {
            DrawerLayout drawerLayout = (DrawerLayout) parent;
            drawerLayout.removeDrawerListener(this.backDrawerListener);
            drawerLayout.addDrawerListener(this.backDrawerListener);
            if (drawerLayout.isDrawerOpen(this)) {
                this.backOrchestrator.startListeningForBackCallbacksWithPriorityOverlay();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.material.internal.ScrimInsetsFrameLayout, android.view.ViewGroup, android.view.View
    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        getViewTreeObserver().removeOnGlobalLayoutListener(this.onGlobalLayoutListener);
        ViewParent parent = getParent();
        if (parent instanceof DrawerLayout) {
            DrawerLayout drawerLayout = (DrawerLayout) parent;
            drawerLayout.removeDrawerListener(this.backDrawerListener);
        }
    }

    @Override // android.view.View
    protected void onSizeChanged(int w, int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
        maybeUpdateCornerSizeForDrawerLayout(w, h);
    }

    @Override // android.view.View
    public void setElevation(float elevation) {
        super.setElevation(elevation);
        MaterialShapeUtils.setElevation(this, elevation);
    }

    private Drawable createDefaultItemBackground(TintTypedArray a) {
        ColorStateList fillColor = MaterialResources.getColorStateList(getContext(), a, R.styleable.NavigationView_itemShapeFillColor);
        return createDefaultItemDrawable(a, fillColor);
    }

    private Drawable createDefaultItemDrawable(TintTypedArray a, ColorStateList fillColor) {
        int shapeAppearanceResId = a.getResourceId(R.styleable.NavigationView_itemShapeAppearance, 0);
        int shapeAppearanceOverlayResId = a.getResourceId(R.styleable.NavigationView_itemShapeAppearanceOverlay, 0);
        MaterialShapeDrawable materialShapeDrawable = new MaterialShapeDrawable(ShapeAppearanceModel.builder(getContext(), shapeAppearanceResId, shapeAppearanceOverlayResId).build());
        materialShapeDrawable.setFillColor(fillColor);
        int insetLeft = a.getDimensionPixelSize(R.styleable.NavigationView_itemShapeInsetStart, 0);
        int insetTop = a.getDimensionPixelSize(R.styleable.NavigationView_itemShapeInsetTop, 0);
        int insetRight = a.getDimensionPixelSize(R.styleable.NavigationView_itemShapeInsetEnd, 0);
        int insetBottom = a.getDimensionPixelSize(R.styleable.NavigationView_itemShapeInsetBottom, 0);
        return new InsetDrawable((Drawable) materialShapeDrawable, insetLeft, insetTop, insetRight, insetBottom);
    }

    @Override // android.view.View
    protected Parcelable onSaveInstanceState() {
        Parcelable superState = super.onSaveInstanceState();
        SavedState state = new SavedState(superState);
        state.menuState = new Bundle();
        this.menu.savePresenterStates(state.menuState);
        return state;
    }

    @Override // android.view.View
    protected void onRestoreInstanceState(Parcelable savedState) {
        if (!(savedState instanceof SavedState)) {
            super.onRestoreInstanceState(savedState);
            return;
        }
        SavedState state = (SavedState) savedState;
        super.onRestoreInstanceState(state.getSuperState());
        this.menu.restorePresenterStates(state.menuState);
    }

    public void setNavigationItemSelectedListener(OnNavigationItemSelectedListener listener) {
        this.listener = listener;
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthSpec, int heightSpec) {
        switch (View.MeasureSpec.getMode(widthSpec)) {
            case Integer.MIN_VALUE:
                widthSpec = View.MeasureSpec.makeMeasureSpec(Math.min(View.MeasureSpec.getSize(widthSpec), this.maxWidth), BasicMeasure.EXACTLY);
                break;
            case 0:
                widthSpec = View.MeasureSpec.makeMeasureSpec(this.maxWidth, BasicMeasure.EXACTLY);
                break;
        }
        super.onMeasure(widthSpec, heightSpec);
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void dispatchDraw(Canvas canvas) {
        this.shapeableDelegate.maybeClip(canvas, new CanvasCompat.CanvasOperation() { // from class: com.google.android.material.navigation.NavigationView$$ExternalSyntheticLambda0
            @Override // com.google.android.material.canvas.CanvasCompat.CanvasOperation
            public final void run(Canvas canvas2) {
                NavigationView.this.m104xb790515(canvas2);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$dispatchDraw$0$com-google-android-material-navigation-NavigationView  reason: not valid java name */
    public /* synthetic */ void m104xb790515(Canvas x$0) {
        super.dispatchDraw(x$0);
    }

    @Override // com.google.android.material.internal.ScrimInsetsFrameLayout
    protected void onInsetsChanged(WindowInsetsCompat insets) {
        this.presenter.dispatchApplyWindowInsets(insets);
    }

    public void inflateMenu(int resId) {
        this.presenter.setUpdateSuspended(true);
        getMenuInflater().inflate(resId, this.menu);
        this.presenter.setUpdateSuspended(false);
        this.presenter.updateMenuView(false);
    }

    public Menu getMenu() {
        return this.menu;
    }

    public View inflateHeaderView(int res) {
        return this.presenter.inflateHeaderView(res);
    }

    public void addHeaderView(View view) {
        this.presenter.addHeaderView(view);
    }

    public void removeHeaderView(View view) {
        this.presenter.removeHeaderView(view);
    }

    public int getHeaderCount() {
        return this.presenter.getHeaderCount();
    }

    public View getHeaderView(int index) {
        return this.presenter.getHeaderView(index);
    }

    public ColorStateList getItemIconTintList() {
        return this.presenter.getItemTintList();
    }

    public void setItemIconTintList(ColorStateList tint) {
        this.presenter.setItemIconTintList(tint);
    }

    public ColorStateList getItemTextColor() {
        return this.presenter.getItemTextColor();
    }

    public void setItemTextColor(ColorStateList textColor) {
        this.presenter.setItemTextColor(textColor);
    }

    public Drawable getItemBackground() {
        return this.presenter.getItemBackground();
    }

    public void setItemBackgroundResource(int resId) {
        setItemBackground(ContextCompat.getDrawable(getContext(), resId));
    }

    public void setItemBackground(Drawable itemBackground) {
        this.presenter.setItemBackground(itemBackground);
    }

    public int getItemHorizontalPadding() {
        return this.presenter.getItemHorizontalPadding();
    }

    public void setItemHorizontalPadding(int padding) {
        this.presenter.setItemHorizontalPadding(padding);
    }

    public void setItemHorizontalPaddingResource(int paddingResource) {
        this.presenter.setItemHorizontalPadding(getResources().getDimensionPixelSize(paddingResource));
    }

    public int getItemVerticalPadding() {
        return this.presenter.getItemVerticalPadding();
    }

    public void setItemVerticalPadding(int padding) {
        this.presenter.setItemVerticalPadding(padding);
    }

    public void setItemVerticalPaddingResource(int paddingResource) {
        this.presenter.setItemVerticalPadding(getResources().getDimensionPixelSize(paddingResource));
    }

    public int getItemIconPadding() {
        return this.presenter.getItemIconPadding();
    }

    public void setItemIconPadding(int padding) {
        this.presenter.setItemIconPadding(padding);
    }

    public void setItemIconPaddingResource(int paddingResource) {
        this.presenter.setItemIconPadding(getResources().getDimensionPixelSize(paddingResource));
    }

    public void setCheckedItem(int id) {
        MenuItem item = this.menu.findItem(id);
        if (item != null) {
            this.presenter.setCheckedItem((MenuItemImpl) item);
        }
    }

    public void setCheckedItem(MenuItem checkedItem) {
        MenuItem item = this.menu.findItem(checkedItem.getItemId());
        if (item != null) {
            this.presenter.setCheckedItem((MenuItemImpl) item);
            return;
        }
        throw new IllegalArgumentException("Called setCheckedItem(MenuItem) with an item that is not in the current menu.");
    }

    public MenuItem getCheckedItem() {
        return this.presenter.getCheckedItem();
    }

    public void setItemTextAppearance(int resId) {
        this.presenter.setItemTextAppearance(resId);
    }

    public void setItemTextAppearanceActiveBoldEnabled(boolean isBold) {
        this.presenter.setItemTextAppearanceActiveBoldEnabled(isBold);
    }

    public void setItemIconSize(int iconSize) {
        this.presenter.setItemIconSize(iconSize);
    }

    public void setItemMaxLines(int itemMaxLines) {
        this.presenter.setItemMaxLines(itemMaxLines);
    }

    public int getItemMaxLines() {
        return this.presenter.getItemMaxLines();
    }

    public boolean isTopInsetScrimEnabled() {
        return this.topInsetScrimEnabled;
    }

    public void setTopInsetScrimEnabled(boolean enabled) {
        this.topInsetScrimEnabled = enabled;
    }

    public boolean isBottomInsetScrimEnabled() {
        return this.bottomInsetScrimEnabled;
    }

    public void setBottomInsetScrimEnabled(boolean enabled) {
        this.bottomInsetScrimEnabled = enabled;
    }

    public int getDividerInsetStart() {
        return this.presenter.getDividerInsetStart();
    }

    public void setDividerInsetStart(int dividerInsetStart) {
        this.presenter.setDividerInsetStart(dividerInsetStart);
    }

    public int getDividerInsetEnd() {
        return this.presenter.getDividerInsetEnd();
    }

    public void setDividerInsetEnd(int dividerInsetEnd) {
        this.presenter.setDividerInsetEnd(dividerInsetEnd);
    }

    public int getSubheaderInsetStart() {
        return this.presenter.getSubheaderInsetStart();
    }

    public void setSubheaderInsetStart(int subheaderInsetStart) {
        this.presenter.setSubheaderInsetStart(subheaderInsetStart);
    }

    public int getSubheaderInsetEnd() {
        return this.presenter.getSubheaderInsetEnd();
    }

    public void setSubheaderInsetEnd(int subheaderInsetEnd) {
        this.presenter.setSubheaderInsetEnd(subheaderInsetEnd);
    }

    @Override // com.google.android.material.motion.MaterialBackHandler
    public void startBackProgress(BackEventCompat backEvent) {
        requireDrawerLayoutParent();
        this.sideContainerBackHelper.startBackProgress(backEvent);
    }

    @Override // com.google.android.material.motion.MaterialBackHandler
    public void updateBackProgress(BackEventCompat backEvent) {
        Pair<DrawerLayout, DrawerLayout.LayoutParams> drawerLayoutPair = requireDrawerLayoutParent();
        this.sideContainerBackHelper.updateBackProgress(backEvent, ((DrawerLayout.LayoutParams) drawerLayoutPair.second).gravity);
    }

    @Override // com.google.android.material.motion.MaterialBackHandler
    public void handleBackInvoked() {
        Pair<DrawerLayout, DrawerLayout.LayoutParams> drawerLayoutPair = requireDrawerLayoutParent();
        DrawerLayout drawerLayout = (DrawerLayout) drawerLayoutPair.first;
        BackEventCompat backEvent = this.sideContainerBackHelper.onHandleBackInvoked();
        if (backEvent == null || Build.VERSION.SDK_INT < 34) {
            drawerLayout.closeDrawer(this);
            return;
        }
        int gravity = ((DrawerLayout.LayoutParams) drawerLayoutPair.second).gravity;
        Animator.AnimatorListener scrimCloseAnimatorListener = DrawerLayoutUtils.getScrimCloseAnimatorListener(drawerLayout, this);
        ValueAnimator.AnimatorUpdateListener scrimCloseAnimatorUpdateListener = DrawerLayoutUtils.getScrimCloseAnimatorUpdateListener(drawerLayout);
        this.sideContainerBackHelper.finishBackProgress(backEvent, gravity, scrimCloseAnimatorListener, scrimCloseAnimatorUpdateListener);
    }

    @Override // com.google.android.material.motion.MaterialBackHandler
    public void cancelBackProgress() {
        requireDrawerLayoutParent();
        this.sideContainerBackHelper.cancelBackProgress();
    }

    private Pair<DrawerLayout, DrawerLayout.LayoutParams> requireDrawerLayoutParent() {
        ViewParent parent = getParent();
        ViewGroup.LayoutParams layoutParams = getLayoutParams();
        if ((parent instanceof DrawerLayout) && (layoutParams instanceof DrawerLayout.LayoutParams)) {
            return new Pair<>((DrawerLayout) parent, (DrawerLayout.LayoutParams) layoutParams);
        }
        throw new IllegalStateException("NavigationView back progress requires the direct parent view to be a DrawerLayout.");
    }

    MaterialSideContainerBackHelper getBackHelper() {
        return this.sideContainerBackHelper;
    }

    private MenuInflater getMenuInflater() {
        if (this.menuInflater == null) {
            this.menuInflater = new SupportMenuInflater(getContext());
        }
        return this.menuInflater;
    }

    private ColorStateList createDefaultColorStateList(int baseColorThemeAttr) {
        TypedValue value = new TypedValue();
        if (getContext().getTheme().resolveAttribute(baseColorThemeAttr, value, true)) {
            ColorStateList baseColor = AppCompatResources.getColorStateList(getContext(), value.resourceId);
            if (getContext().getTheme().resolveAttribute(androidx.appcompat.R.attr.colorPrimary, value, true)) {
                int colorPrimary = value.data;
                int defaultColor = baseColor.getDefaultColor();
                return new ColorStateList(new int[][]{DISABLED_STATE_SET, CHECKED_STATE_SET, EMPTY_STATE_SET}, new int[]{baseColor.getColorForState(DISABLED_STATE_SET, defaultColor), colorPrimary, defaultColor});
            }
            return null;
        }
        return null;
    }

    private void setupInsetScrimsListener() {
        this.onGlobalLayoutListener = new ViewTreeObserver.OnGlobalLayoutListener() { // from class: com.google.android.material.navigation.NavigationView.3
            @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
            public void onGlobalLayout() {
                NavigationView.this.getLocationOnScreen(NavigationView.this.tmpLocation);
                boolean isOnRightSide = true;
                boolean isBehindStatusBar = NavigationView.this.tmpLocation[1] == 0;
                NavigationView.this.presenter.setBehindStatusBar(isBehindStatusBar);
                NavigationView.this.setDrawTopInsetForeground(isBehindStatusBar && NavigationView.this.isTopInsetScrimEnabled());
                boolean isOnLeftSide = NavigationView.this.tmpLocation[0] == 0 || NavigationView.this.tmpLocation[0] + NavigationView.this.getWidth() == 0;
                NavigationView.this.setDrawLeftInsetForeground(isOnLeftSide);
                Activity activity = ContextUtils.getActivity(NavigationView.this.getContext());
                if (activity != null) {
                    Rect displayBounds = WindowUtils.getCurrentWindowBounds(activity);
                    boolean isBehindSystemNav = displayBounds.height() - NavigationView.this.getHeight() == NavigationView.this.tmpLocation[1];
                    boolean hasNonZeroAlpha = Color.alpha(activity.getWindow().getNavigationBarColor()) != 0;
                    NavigationView.this.setDrawBottomInsetForeground(isBehindSystemNav && hasNonZeroAlpha && NavigationView.this.isBottomInsetScrimEnabled());
                    if (displayBounds.width() != NavigationView.this.tmpLocation[0] && displayBounds.width() - NavigationView.this.getWidth() != NavigationView.this.tmpLocation[0]) {
                        isOnRightSide = false;
                    }
                    NavigationView.this.setDrawRightInsetForeground(isOnRightSide);
                }
            }
        };
        getViewTreeObserver().addOnGlobalLayoutListener(this.onGlobalLayoutListener);
    }

    /* loaded from: classes.dex */
    public static class SavedState extends AbsSavedState {
        public static final Parcelable.Creator<SavedState> CREATOR = new Parcelable.ClassLoaderCreator<SavedState>() { // from class: com.google.android.material.navigation.NavigationView.SavedState.1
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.os.Parcelable.ClassLoaderCreator
            public SavedState createFromParcel(Parcel in, ClassLoader loader) {
                return new SavedState(in, loader);
            }

            @Override // android.os.Parcelable.Creator
            public SavedState createFromParcel(Parcel in) {
                return new SavedState(in, null);
            }

            @Override // android.os.Parcelable.Creator
            public SavedState[] newArray(int size) {
                return new SavedState[size];
            }
        };
        public Bundle menuState;

        public SavedState(Parcel in, ClassLoader loader) {
            super(in, loader);
            this.menuState = in.readBundle(loader);
        }

        public SavedState(Parcelable superState) {
            super(superState);
        }

        @Override // androidx.customview.view.AbsSavedState, android.os.Parcelable
        public void writeToParcel(Parcel dest, int flags) {
            super.writeToParcel(dest, flags);
            dest.writeBundle(this.menuState);
        }
    }
}
