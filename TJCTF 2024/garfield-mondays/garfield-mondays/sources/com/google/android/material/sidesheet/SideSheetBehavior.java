package com.google.android.material.sidesheet;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewParent;
import androidx.activity.BackEventCompat;
import androidx.constraintlayout.core.widgets.analyzer.BasicMeasure;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.math.MathUtils;
import androidx.core.view.GravityCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import androidx.core.view.accessibility.AccessibilityViewCommand;
import androidx.customview.view.AbsSavedState;
import androidx.customview.widget.ViewDragHelper;
import com.google.android.material.R;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.motion.MaterialSideContainerBackHelper;
import com.google.android.material.resources.MaterialResources;
import com.google.android.material.shape.MaterialShapeDrawable;
import com.google.android.material.shape.ShapeAppearanceModel;
import com.google.android.material.sidesheet.SideSheetBehavior;
import java.lang.ref.WeakReference;
import java.util.LinkedHashSet;
import java.util.Set;
/* loaded from: classes.dex */
public class SideSheetBehavior<V extends View> extends CoordinatorLayout.Behavior<V> implements Sheet<SideSheetCallback> {
    private static final int DEFAULT_ACCESSIBILITY_PANE_TITLE = R.string.side_sheet_accessibility_pane_title;
    private static final int DEF_STYLE_RES = R.style.Widget_Material3_SideSheet;
    private static final float HIDE_FRICTION = 0.1f;
    private static final float HIDE_THRESHOLD = 0.5f;
    private static final int NO_MAX_SIZE = -1;
    static final int SIGNIFICANT_VEL_THRESHOLD = 500;
    private ColorStateList backgroundTint;
    private final Set<SideSheetCallback> callbacks;
    private int childWidth;
    private int coplanarSiblingViewId;
    private WeakReference<View> coplanarSiblingViewRef;
    private final ViewDragHelper.Callback dragCallback;
    private boolean draggable;
    private float elevation;
    private float hideFriction;
    private boolean ignoreEvents;
    private int initialX;
    private int innerMargin;
    private int lastStableState;
    private MaterialShapeDrawable materialShapeDrawable;
    private float maximumVelocity;
    private int parentInnerEdge;
    private int parentWidth;
    private ShapeAppearanceModel shapeAppearanceModel;
    private SheetDelegate sheetDelegate;
    private MaterialSideContainerBackHelper sideContainerBackHelper;
    private int state;
    private final SideSheetBehavior<V>.StateSettlingTracker stateSettlingTracker;
    private VelocityTracker velocityTracker;
    private ViewDragHelper viewDragHelper;
    private WeakReference<V> viewRef;

    public SideSheetBehavior() {
        this.stateSettlingTracker = new StateSettlingTracker();
        this.draggable = true;
        this.state = 5;
        this.lastStableState = 5;
        this.hideFriction = 0.1f;
        this.coplanarSiblingViewId = -1;
        this.callbacks = new LinkedHashSet();
        this.dragCallback = new ViewDragHelper.Callback() { // from class: com.google.android.material.sidesheet.SideSheetBehavior.1
            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public boolean tryCaptureView(View child, int pointerId) {
                return (SideSheetBehavior.this.state == 1 || SideSheetBehavior.this.viewRef == null || SideSheetBehavior.this.viewRef.get() != child) ? false : true;
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public void onViewPositionChanged(View changedView, int left, int top, int dx, int dy) {
                ViewGroup.MarginLayoutParams layoutParams;
                View coplanarSiblingView = SideSheetBehavior.this.getCoplanarSiblingView();
                if (coplanarSiblingView != null && (layoutParams = (ViewGroup.MarginLayoutParams) coplanarSiblingView.getLayoutParams()) != null) {
                    SideSheetBehavior.this.sheetDelegate.updateCoplanarSiblingLayoutParams(layoutParams, changedView.getLeft(), changedView.getRight());
                    coplanarSiblingView.setLayoutParams(layoutParams);
                }
                SideSheetBehavior.this.dispatchOnSlide(changedView, left);
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public void onViewDragStateChanged(int state) {
                if (state == 1 && SideSheetBehavior.this.draggable) {
                    SideSheetBehavior.this.setStateInternal(1);
                }
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public void onViewReleased(View releasedChild, float xVelocity, float yVelocity) {
                int targetState = SideSheetBehavior.this.calculateTargetStateOnViewReleased(releasedChild, xVelocity, yVelocity);
                SideSheetBehavior.this.startSettling(releasedChild, targetState, SideSheetBehavior.this.shouldSkipSmoothAnimation());
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public int clampViewPositionVertical(View child, int top, int dy) {
                return child.getTop();
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public int clampViewPositionHorizontal(View child, int left, int dx) {
                return MathUtils.clamp(left, SideSheetBehavior.this.sheetDelegate.getMinViewPositionHorizontal(), SideSheetBehavior.this.sheetDelegate.getMaxViewPositionHorizontal());
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public int getViewHorizontalDragRange(View child) {
                return SideSheetBehavior.this.childWidth + SideSheetBehavior.this.getInnerMargin();
            }
        };
    }

    public SideSheetBehavior(Context context, AttributeSet attrs) {
        super(context, attrs);
        this.stateSettlingTracker = new StateSettlingTracker();
        this.draggable = true;
        this.state = 5;
        this.lastStableState = 5;
        this.hideFriction = 0.1f;
        this.coplanarSiblingViewId = -1;
        this.callbacks = new LinkedHashSet();
        this.dragCallback = new ViewDragHelper.Callback() { // from class: com.google.android.material.sidesheet.SideSheetBehavior.1
            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public boolean tryCaptureView(View child, int pointerId) {
                return (SideSheetBehavior.this.state == 1 || SideSheetBehavior.this.viewRef == null || SideSheetBehavior.this.viewRef.get() != child) ? false : true;
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public void onViewPositionChanged(View changedView, int left, int top, int dx, int dy) {
                ViewGroup.MarginLayoutParams layoutParams;
                View coplanarSiblingView = SideSheetBehavior.this.getCoplanarSiblingView();
                if (coplanarSiblingView != null && (layoutParams = (ViewGroup.MarginLayoutParams) coplanarSiblingView.getLayoutParams()) != null) {
                    SideSheetBehavior.this.sheetDelegate.updateCoplanarSiblingLayoutParams(layoutParams, changedView.getLeft(), changedView.getRight());
                    coplanarSiblingView.setLayoutParams(layoutParams);
                }
                SideSheetBehavior.this.dispatchOnSlide(changedView, left);
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public void onViewDragStateChanged(int state) {
                if (state == 1 && SideSheetBehavior.this.draggable) {
                    SideSheetBehavior.this.setStateInternal(1);
                }
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public void onViewReleased(View releasedChild, float xVelocity, float yVelocity) {
                int targetState = SideSheetBehavior.this.calculateTargetStateOnViewReleased(releasedChild, xVelocity, yVelocity);
                SideSheetBehavior.this.startSettling(releasedChild, targetState, SideSheetBehavior.this.shouldSkipSmoothAnimation());
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public int clampViewPositionVertical(View child, int top, int dy) {
                return child.getTop();
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public int clampViewPositionHorizontal(View child, int left, int dx) {
                return MathUtils.clamp(left, SideSheetBehavior.this.sheetDelegate.getMinViewPositionHorizontal(), SideSheetBehavior.this.sheetDelegate.getMaxViewPositionHorizontal());
            }

            @Override // androidx.customview.widget.ViewDragHelper.Callback
            public int getViewHorizontalDragRange(View child) {
                return SideSheetBehavior.this.childWidth + SideSheetBehavior.this.getInnerMargin();
            }
        };
        TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.SideSheetBehavior_Layout);
        if (a.hasValue(R.styleable.SideSheetBehavior_Layout_backgroundTint)) {
            this.backgroundTint = MaterialResources.getColorStateList(context, a, R.styleable.SideSheetBehavior_Layout_backgroundTint);
        }
        if (a.hasValue(R.styleable.SideSheetBehavior_Layout_shapeAppearance)) {
            this.shapeAppearanceModel = ShapeAppearanceModel.builder(context, attrs, 0, DEF_STYLE_RES).build();
        }
        if (a.hasValue(R.styleable.SideSheetBehavior_Layout_coplanarSiblingViewId)) {
            setCoplanarSiblingViewId(a.getResourceId(R.styleable.SideSheetBehavior_Layout_coplanarSiblingViewId, -1));
        }
        createMaterialShapeDrawableIfNeeded(context);
        this.elevation = a.getDimension(R.styleable.SideSheetBehavior_Layout_android_elevation, -1.0f);
        setDraggable(a.getBoolean(R.styleable.SideSheetBehavior_Layout_behavior_draggable, true));
        a.recycle();
        ViewConfiguration configuration = ViewConfiguration.get(context);
        this.maximumVelocity = configuration.getScaledMaximumFlingVelocity();
    }

    private void setSheetEdge(V view, int layoutDirection) {
        CoordinatorLayout.LayoutParams params = (CoordinatorLayout.LayoutParams) view.getLayoutParams();
        int sheetGravity = GravityCompat.getAbsoluteGravity(params.gravity, layoutDirection);
        setSheetEdge(sheetGravity == 3 ? 1 : 0);
    }

    private void setSheetEdge(int sheetEdge) {
        if (this.sheetDelegate == null || this.sheetDelegate.getSheetEdge() != sheetEdge) {
            if (sheetEdge == 0) {
                this.sheetDelegate = new RightSheetDelegate(this);
                if (this.shapeAppearanceModel != null && !hasRightMargin()) {
                    ShapeAppearanceModel.Builder builder = this.shapeAppearanceModel.toBuilder();
                    builder.setTopRightCornerSize(0.0f).setBottomRightCornerSize(0.0f);
                    updateMaterialShapeDrawable(builder.build());
                }
            } else if (sheetEdge == 1) {
                this.sheetDelegate = new LeftSheetDelegate(this);
                if (this.shapeAppearanceModel != null && !hasLeftMargin()) {
                    ShapeAppearanceModel.Builder builder2 = this.shapeAppearanceModel.toBuilder();
                    builder2.setTopLeftCornerSize(0.0f).setBottomLeftCornerSize(0.0f);
                    updateMaterialShapeDrawable(builder2.build());
                }
            } else {
                throw new IllegalArgumentException("Invalid sheet edge position value: " + sheetEdge + ". Must be 0 or 1.");
            }
        }
    }

    private int getGravityFromSheetEdge() {
        return (this.sheetDelegate == null || this.sheetDelegate.getSheetEdge() == 0) ? 5 : 3;
    }

    private boolean hasRightMargin() {
        CoordinatorLayout.LayoutParams layoutParams = getViewLayoutParams();
        return layoutParams != null && layoutParams.rightMargin > 0;
    }

    private boolean hasLeftMargin() {
        CoordinatorLayout.LayoutParams layoutParams = getViewLayoutParams();
        return layoutParams != null && layoutParams.leftMargin > 0;
    }

    private CoordinatorLayout.LayoutParams getViewLayoutParams() {
        View view;
        if (this.viewRef != null && (view = this.viewRef.get()) != null && (view.getLayoutParams() instanceof CoordinatorLayout.LayoutParams)) {
            return (CoordinatorLayout.LayoutParams) view.getLayoutParams();
        }
        return null;
    }

    private void updateMaterialShapeDrawable(ShapeAppearanceModel shapeAppearanceModel) {
        if (this.materialShapeDrawable != null) {
            this.materialShapeDrawable.setShapeAppearanceModel(shapeAppearanceModel);
        }
    }

    public void expand() {
        setState(3);
    }

    public void hide() {
        setState(5);
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public Parcelable onSaveInstanceState(CoordinatorLayout parent, V child) {
        return new SavedState(super.onSaveInstanceState(parent, child), (SideSheetBehavior<?>) this);
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public void onRestoreInstanceState(CoordinatorLayout parent, V child, Parcelable state) {
        SavedState ss = (SavedState) state;
        if (ss.getSuperState() != null) {
            super.onRestoreInstanceState(parent, child, ss.getSuperState());
        }
        this.state = (ss.state == 1 || ss.state == 2) ? 5 : ss.state;
        this.lastStableState = this.state;
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public void onAttachedToLayoutParams(CoordinatorLayout.LayoutParams layoutParams) {
        super.onAttachedToLayoutParams(layoutParams);
        this.viewRef = null;
        this.viewDragHelper = null;
        this.sideContainerBackHelper = null;
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public void onDetachedFromLayoutParams() {
        super.onDetachedFromLayoutParams();
        this.viewRef = null;
        this.viewDragHelper = null;
        this.sideContainerBackHelper = null;
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public boolean onMeasureChild(CoordinatorLayout parent, V child, int parentWidthMeasureSpec, int widthUsed, int parentHeightMeasureSpec, int heightUsed) {
        ViewGroup.MarginLayoutParams lp = (ViewGroup.MarginLayoutParams) child.getLayoutParams();
        int childWidthMeasureSpec = getChildMeasureSpec(parentWidthMeasureSpec, parent.getPaddingLeft() + parent.getPaddingRight() + lp.leftMargin + lp.rightMargin + widthUsed, -1, lp.width);
        int childHeightMeasureSpec = getChildMeasureSpec(parentHeightMeasureSpec, parent.getPaddingTop() + parent.getPaddingBottom() + lp.topMargin + lp.bottomMargin + heightUsed, -1, lp.height);
        child.measure(childWidthMeasureSpec, childHeightMeasureSpec);
        return true;
    }

    private int getChildMeasureSpec(int parentMeasureSpec, int padding, int maxSize, int childDimension) {
        int result = ViewGroup.getChildMeasureSpec(parentMeasureSpec, padding, childDimension);
        if (maxSize == -1) {
            return result;
        }
        int mode = View.MeasureSpec.getMode(result);
        int size = View.MeasureSpec.getSize(result);
        switch (mode) {
            case BasicMeasure.EXACTLY /* 1073741824 */:
                return View.MeasureSpec.makeMeasureSpec(Math.min(size, maxSize), BasicMeasure.EXACTLY);
            default:
                return View.MeasureSpec.makeMeasureSpec(size == 0 ? maxSize : Math.min(size, maxSize), Integer.MIN_VALUE);
        }
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public boolean onLayoutChild(CoordinatorLayout parent, V child, int layoutDirection) {
        if (ViewCompat.getFitsSystemWindows(parent) && !ViewCompat.getFitsSystemWindows(child)) {
            child.setFitsSystemWindows(true);
        }
        if (this.viewRef == null) {
            this.viewRef = new WeakReference<>(child);
            this.sideContainerBackHelper = new MaterialSideContainerBackHelper(child);
            if (this.materialShapeDrawable != null) {
                ViewCompat.setBackground(child, this.materialShapeDrawable);
                this.materialShapeDrawable.setElevation(this.elevation == -1.0f ? ViewCompat.getElevation(child) : this.elevation);
            } else if (this.backgroundTint != null) {
                ViewCompat.setBackgroundTintList(child, this.backgroundTint);
            }
            updateSheetVisibility(child);
            updateAccessibilityActions();
            if (ViewCompat.getImportantForAccessibility(child) == 0) {
                ViewCompat.setImportantForAccessibility(child, 1);
            }
            ensureAccessibilityPaneTitleIsSet(child);
        }
        setSheetEdge(child, layoutDirection);
        if (this.viewDragHelper == null) {
            this.viewDragHelper = ViewDragHelper.create(parent, this.dragCallback);
        }
        int savedOuterEdge = this.sheetDelegate.getOuterEdge(child);
        parent.onLayoutChild(child, layoutDirection);
        this.parentWidth = parent.getWidth();
        this.parentInnerEdge = this.sheetDelegate.getParentInnerEdge(parent);
        this.childWidth = child.getWidth();
        ViewGroup.MarginLayoutParams margins = (ViewGroup.MarginLayoutParams) child.getLayoutParams();
        this.innerMargin = margins != null ? this.sheetDelegate.calculateInnerMargin(margins) : 0;
        int currentOffset = calculateCurrentOffset(savedOuterEdge, child);
        ViewCompat.offsetLeftAndRight(child, currentOffset);
        maybeAssignCoplanarSiblingViewBasedId(parent);
        for (SheetCallback callback : this.callbacks) {
            if (callback instanceof SideSheetCallback) {
                SideSheetCallback sideSheetCallback = (SideSheetCallback) callback;
                sideSheetCallback.onLayout(child);
            }
        }
        return true;
    }

    private void updateSheetVisibility(View sheet) {
        int visibility = this.state == 5 ? 4 : 0;
        if (sheet.getVisibility() != visibility) {
            sheet.setVisibility(visibility);
        }
    }

    private void ensureAccessibilityPaneTitleIsSet(View sheet) {
        if (ViewCompat.getAccessibilityPaneTitle(sheet) == null) {
            ViewCompat.setAccessibilityPaneTitle(sheet, sheet.getResources().getString(DEFAULT_ACCESSIBILITY_PANE_TITLE));
        }
    }

    private void maybeAssignCoplanarSiblingViewBasedId(CoordinatorLayout parent) {
        View coplanarSiblingView;
        if (this.coplanarSiblingViewRef == null && this.coplanarSiblingViewId != -1 && (coplanarSiblingView = parent.findViewById(this.coplanarSiblingViewId)) != null) {
            this.coplanarSiblingViewRef = new WeakReference<>(coplanarSiblingView);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getChildWidth() {
        return this.childWidth;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getParentWidth() {
        return this.parentWidth;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getParentInnerEdge() {
        return this.parentInnerEdge;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getInnerMargin() {
        return this.innerMargin;
    }

    private int calculateCurrentOffset(int savedOuterEdge, V child) {
        switch (this.state) {
            case 1:
            case 2:
                int currentOffset = savedOuterEdge - this.sheetDelegate.getOuterEdge(child);
                return currentOffset;
            case 3:
                return 0;
            case 4:
            default:
                throw new IllegalStateException("Unexpected value: " + this.state);
            case 5:
                int currentOffset2 = this.sheetDelegate.getHiddenOffset();
                return currentOffset2;
        }
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public boolean onInterceptTouchEvent(CoordinatorLayout parent, V child, MotionEvent event) {
        if (!shouldInterceptTouchEvent(child)) {
            this.ignoreEvents = true;
            return false;
        }
        int action = event.getActionMasked();
        if (action == 0) {
            resetVelocity();
        }
        if (this.velocityTracker == null) {
            this.velocityTracker = VelocityTracker.obtain();
        }
        this.velocityTracker.addMovement(event);
        switch (action) {
            case 0:
                this.initialX = (int) event.getX();
                break;
            case 1:
            case 3:
                if (this.ignoreEvents) {
                    this.ignoreEvents = false;
                    return false;
                }
                break;
        }
        return (this.ignoreEvents || this.viewDragHelper == null || !this.viewDragHelper.shouldInterceptTouchEvent(event)) ? false : true;
    }

    private boolean shouldInterceptTouchEvent(V child) {
        return (child.isShown() || ViewCompat.getAccessibilityPaneTitle(child) != null) && this.draggable;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getSignificantVelocityThreshold() {
        return SIGNIFICANT_VEL_THRESHOLD;
    }

    @Override // androidx.coordinatorlayout.widget.CoordinatorLayout.Behavior
    public boolean onTouchEvent(CoordinatorLayout parent, V child, MotionEvent event) {
        if (!child.isShown()) {
            return false;
        }
        int action = event.getActionMasked();
        if (this.state == 1 && action == 0) {
            return true;
        }
        if (shouldHandleDraggingWithHelper()) {
            this.viewDragHelper.processTouchEvent(event);
        }
        if (action == 0) {
            resetVelocity();
        }
        if (this.velocityTracker == null) {
            this.velocityTracker = VelocityTracker.obtain();
        }
        this.velocityTracker.addMovement(event);
        if (shouldHandleDraggingWithHelper() && action == 2 && !this.ignoreEvents && isDraggedFarEnough(event)) {
            this.viewDragHelper.captureChildView(child, event.getPointerId(event.getActionIndex()));
        }
        return !this.ignoreEvents;
    }

    private boolean isDraggedFarEnough(MotionEvent event) {
        if (shouldHandleDraggingWithHelper()) {
            float distanceDragged = calculateDragDistance(this.initialX, event.getX());
            return distanceDragged > ((float) this.viewDragHelper.getTouchSlop());
        }
        return false;
    }

    private float calculateDragDistance(float initialPoint, float currentPoint) {
        return Math.abs(initialPoint - currentPoint);
    }

    public int getExpandedOffset() {
        return this.sheetDelegate.getExpandedOffset();
    }

    public void setDraggable(boolean draggable) {
        this.draggable = draggable;
    }

    public boolean isDraggable() {
        return this.draggable;
    }

    public void setHideFriction(float hideFriction) {
        this.hideFriction = hideFriction;
    }

    public float getHideFriction() {
        return this.hideFriction;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getHideThreshold() {
        return 0.5f;
    }

    @Override // com.google.android.material.sidesheet.Sheet
    public void addCallback(SideSheetCallback callback) {
        this.callbacks.add(callback);
    }

    @Override // com.google.android.material.sidesheet.Sheet
    public void removeCallback(SideSheetCallback callback) {
        this.callbacks.remove(callback);
    }

    @Override // com.google.android.material.sidesheet.Sheet
    public void setState(final int state) {
        if (state == 1 || state == 2) {
            throw new IllegalArgumentException("STATE_" + (state == 1 ? "DRAGGING" : "SETTLING") + " should not be set externally.");
        } else if (this.viewRef == null || this.viewRef.get() == null) {
            setStateInternal(state);
        } else {
            runAfterLayout(this.viewRef.get(), new Runnable() { // from class: com.google.android.material.sidesheet.SideSheetBehavior$$ExternalSyntheticLambda1
                @Override // java.lang.Runnable
                public final void run() {
                    SideSheetBehavior.this.m122xc0f1d0a9(state);
                }
            });
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$setState$0$com-google-android-material-sidesheet-SideSheetBehavior  reason: not valid java name */
    public /* synthetic */ void m122xc0f1d0a9(int finalState) {
        V child = this.viewRef.get();
        if (child != null) {
            startSettling(child, finalState, false);
        }
    }

    private void runAfterLayout(V child, Runnable runnable) {
        if (isLayingOut(child)) {
            child.post(runnable);
        } else {
            runnable.run();
        }
    }

    private boolean isLayingOut(V child) {
        ViewParent parent = child.getParent();
        return parent != null && parent.isLayoutRequested() && ViewCompat.isAttachedToWindow(child);
    }

    @Override // com.google.android.material.sidesheet.Sheet
    public int getState() {
        return this.state;
    }

    void setStateInternal(int state) {
        View sheet;
        if (this.state == state) {
            return;
        }
        this.state = state;
        if (state == 3 || state == 5) {
            this.lastStableState = state;
        }
        if (this.viewRef == null || (sheet = this.viewRef.get()) == null) {
            return;
        }
        updateSheetVisibility(sheet);
        for (SheetCallback callback : this.callbacks) {
            callback.onStateChanged(sheet, state);
        }
        updateAccessibilityActions();
    }

    private void resetVelocity() {
        if (this.velocityTracker != null) {
            this.velocityTracker.recycle();
            this.velocityTracker = null;
        }
    }

    boolean shouldHide(View child, float velocity) {
        return this.sheetDelegate.shouldHide(child, velocity);
    }

    private boolean shouldHandleDraggingWithHelper() {
        return this.viewDragHelper != null && (this.draggable || this.state == 1);
    }

    private void createMaterialShapeDrawableIfNeeded(Context context) {
        if (this.shapeAppearanceModel == null) {
            return;
        }
        this.materialShapeDrawable = new MaterialShapeDrawable(this.shapeAppearanceModel);
        this.materialShapeDrawable.initializeElevationOverlay(context);
        if (this.backgroundTint != null) {
            this.materialShapeDrawable.setFillColor(this.backgroundTint);
            return;
        }
        TypedValue defaultColor = new TypedValue();
        context.getTheme().resolveAttribute(16842801, defaultColor, true);
        this.materialShapeDrawable.setTint(defaultColor.data);
    }

    float getXVelocity() {
        if (this.velocityTracker == null) {
            return 0.0f;
        }
        this.velocityTracker.computeCurrentVelocity(1000, this.maximumVelocity);
        return this.velocityTracker.getXVelocity();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startSettling(View child, int state, boolean isReleasingView) {
        boolean settling = isSettling(child, state, isReleasingView);
        if (settling) {
            setStateInternal(2);
            this.stateSettlingTracker.continueSettlingToState(state);
            return;
        }
        setStateInternal(state);
    }

    private boolean isSettling(View child, int state, boolean isReleasingView) {
        int left = getOuterEdgeOffsetForState(state);
        ViewDragHelper viewDragHelper = getViewDragHelper();
        return viewDragHelper != null && (!isReleasingView ? !viewDragHelper.smoothSlideViewTo(child, left, child.getTop()) : !viewDragHelper.settleCapturedViewAt(left, child.getTop()));
    }

    int getOuterEdgeOffsetForState(int state) {
        switch (state) {
            case 3:
                return getExpandedOffset();
            case 4:
            default:
                throw new IllegalArgumentException("Invalid state to get outer edge offset: " + state);
            case 5:
                return this.sheetDelegate.getHiddenOffset();
        }
    }

    ViewDragHelper getViewDragHelper() {
        return this.viewDragHelper;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int calculateTargetStateOnViewReleased(View releasedChild, float xVelocity, float yVelocity) {
        if (isExpandingOutwards(xVelocity)) {
            return 3;
        }
        if (shouldHide(releasedChild, xVelocity)) {
            if (this.sheetDelegate.isSwipeSignificant(xVelocity, yVelocity) || this.sheetDelegate.isReleasedCloseToInnerEdge(releasedChild)) {
                return 5;
            }
            return 3;
        } else if (xVelocity == 0.0f || !SheetUtils.isSwipeMostlyHorizontal(xVelocity, yVelocity)) {
            int currentLeft = releasedChild.getLeft();
            if (Math.abs(currentLeft - getExpandedOffset()) < Math.abs(currentLeft - this.sheetDelegate.getHiddenOffset())) {
                return 3;
            }
            return 5;
        } else {
            return 5;
        }
    }

    private boolean isExpandingOutwards(float xVelocity) {
        return this.sheetDelegate.isExpandingOutwards(xVelocity);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void dispatchOnSlide(View child, int outerEdge) {
        if (!this.callbacks.isEmpty()) {
            float slideOffset = this.sheetDelegate.calculateSlideOffset(outerEdge);
            for (SheetCallback callback : this.callbacks) {
                callback.onSlide(child, slideOffset);
            }
        }
    }

    public void setCoplanarSiblingViewId(int coplanarSiblingViewId) {
        this.coplanarSiblingViewId = coplanarSiblingViewId;
        clearCoplanarSiblingView();
        if (this.viewRef != null) {
            View view = this.viewRef.get();
            if (coplanarSiblingViewId != -1 && ViewCompat.isLaidOut(view)) {
                view.requestLayout();
            }
        }
    }

    public void setCoplanarSiblingView(View coplanarSiblingView) {
        this.coplanarSiblingViewId = -1;
        if (coplanarSiblingView == null) {
            clearCoplanarSiblingView();
            return;
        }
        this.coplanarSiblingViewRef = new WeakReference<>(coplanarSiblingView);
        if (this.viewRef != null) {
            View view = this.viewRef.get();
            if (ViewCompat.isLaidOut(view)) {
                view.requestLayout();
            }
        }
    }

    public View getCoplanarSiblingView() {
        if (this.coplanarSiblingViewRef != null) {
            return this.coplanarSiblingViewRef.get();
        }
        return null;
    }

    private void clearCoplanarSiblingView() {
        if (this.coplanarSiblingViewRef != null) {
            this.coplanarSiblingViewRef.clear();
        }
        this.coplanarSiblingViewRef = null;
    }

    public boolean shouldSkipSmoothAnimation() {
        return true;
    }

    public int getLastStableState() {
        return this.lastStableState;
    }

    @Override // com.google.android.material.motion.MaterialBackHandler
    public void startBackProgress(BackEventCompat backEvent) {
        if (this.sideContainerBackHelper == null) {
            return;
        }
        this.sideContainerBackHelper.startBackProgress(backEvent);
    }

    @Override // com.google.android.material.motion.MaterialBackHandler
    public void updateBackProgress(BackEventCompat backEvent) {
        if (this.sideContainerBackHelper == null) {
            return;
        }
        this.sideContainerBackHelper.updateBackProgress(backEvent, getGravityFromSheetEdge());
        updateCoplanarSiblingBackProgress();
    }

    private void updateCoplanarSiblingBackProgress() {
        ViewGroup.MarginLayoutParams coplanarSiblingLayoutParams;
        if (this.viewRef == null || this.viewRef.get() == null) {
            return;
        }
        View sheet = this.viewRef.get();
        View coplanarSiblingView = getCoplanarSiblingView();
        if (coplanarSiblingView == null || (coplanarSiblingLayoutParams = (ViewGroup.MarginLayoutParams) coplanarSiblingView.getLayoutParams()) == null) {
            return;
        }
        int updatedCoplanarSiblingAdjacentMargin = (int) ((this.childWidth * sheet.getScaleX()) + this.innerMargin);
        this.sheetDelegate.updateCoplanarSiblingAdjacentMargin(coplanarSiblingLayoutParams, updatedCoplanarSiblingAdjacentMargin);
        coplanarSiblingView.requestLayout();
    }

    @Override // com.google.android.material.motion.MaterialBackHandler
    public void handleBackInvoked() {
        if (this.sideContainerBackHelper == null) {
            return;
        }
        BackEventCompat backEvent = this.sideContainerBackHelper.onHandleBackInvoked();
        if (backEvent == null || Build.VERSION.SDK_INT < 34) {
            setState(5);
        } else {
            this.sideContainerBackHelper.finishBackProgress(backEvent, getGravityFromSheetEdge(), new AnimatorListenerAdapter() { // from class: com.google.android.material.sidesheet.SideSheetBehavior.2
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    SideSheetBehavior.this.setStateInternal(5);
                    if (SideSheetBehavior.this.viewRef != null && SideSheetBehavior.this.viewRef.get() != null) {
                        ((View) SideSheetBehavior.this.viewRef.get()).requestLayout();
                    }
                }
            }, getCoplanarFinishAnimatorUpdateListener());
        }
    }

    private ValueAnimator.AnimatorUpdateListener getCoplanarFinishAnimatorUpdateListener() {
        final ViewGroup.MarginLayoutParams coplanarSiblingLayoutParams;
        final View coplanarSiblingView = getCoplanarSiblingView();
        if (coplanarSiblingView == null || (coplanarSiblingLayoutParams = (ViewGroup.MarginLayoutParams) coplanarSiblingView.getLayoutParams()) == null) {
            return null;
        }
        final int coplanarSiblingAdjacentMargin = this.sheetDelegate.getCoplanarSiblingAdjacentMargin(coplanarSiblingLayoutParams);
        return new ValueAnimator.AnimatorUpdateListener() { // from class: com.google.android.material.sidesheet.SideSheetBehavior$$ExternalSyntheticLambda0
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                SideSheetBehavior.this.m121xc3af8fb4(coplanarSiblingLayoutParams, coplanarSiblingAdjacentMargin, coplanarSiblingView, valueAnimator);
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$getCoplanarFinishAnimatorUpdateListener$1$com-google-android-material-sidesheet-SideSheetBehavior  reason: not valid java name */
    public /* synthetic */ void m121xc3af8fb4(ViewGroup.MarginLayoutParams coplanarSiblingLayoutParams, int coplanarSiblingAdjacentMargin, View coplanarSiblingView, ValueAnimator animation) {
        this.sheetDelegate.updateCoplanarSiblingAdjacentMargin(coplanarSiblingLayoutParams, AnimationUtils.lerp(coplanarSiblingAdjacentMargin, 0, animation.getAnimatedFraction()));
        coplanarSiblingView.requestLayout();
    }

    @Override // com.google.android.material.motion.MaterialBackHandler
    public void cancelBackProgress() {
        if (this.sideContainerBackHelper == null) {
            return;
        }
        this.sideContainerBackHelper.cancelBackProgress();
    }

    MaterialSideContainerBackHelper getBackHelper() {
        return this.sideContainerBackHelper;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class StateSettlingTracker {
        private final Runnable continueSettlingRunnable = new Runnable() { // from class: com.google.android.material.sidesheet.SideSheetBehavior$StateSettlingTracker$$ExternalSyntheticLambda0
            @Override // java.lang.Runnable
            public final void run() {
                SideSheetBehavior.StateSettlingTracker.this.m123xe5f914a3();
            }
        };
        private boolean isContinueSettlingRunnablePosted;
        private int targetState;

        StateSettlingTracker() {
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* renamed from: lambda$new$0$com-google-android-material-sidesheet-SideSheetBehavior$StateSettlingTracker  reason: not valid java name */
        public /* synthetic */ void m123xe5f914a3() {
            this.isContinueSettlingRunnablePosted = false;
            if (SideSheetBehavior.this.viewDragHelper == null || !SideSheetBehavior.this.viewDragHelper.continueSettling(true)) {
                if (SideSheetBehavior.this.state == 2) {
                    SideSheetBehavior.this.setStateInternal(this.targetState);
                    return;
                }
                return;
            }
            continueSettlingToState(this.targetState);
        }

        void continueSettlingToState(int targetState) {
            if (SideSheetBehavior.this.viewRef == null || SideSheetBehavior.this.viewRef.get() == null) {
                return;
            }
            this.targetState = targetState;
            if (!this.isContinueSettlingRunnablePosted) {
                ViewCompat.postOnAnimation((View) SideSheetBehavior.this.viewRef.get(), this.continueSettlingRunnable);
                this.isContinueSettlingRunnablePosted = true;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* loaded from: classes.dex */
    public static class SavedState extends AbsSavedState {
        public static final Parcelable.Creator<SavedState> CREATOR = new Parcelable.ClassLoaderCreator<SavedState>() { // from class: com.google.android.material.sidesheet.SideSheetBehavior.SavedState.1
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // android.os.Parcelable.ClassLoaderCreator
            public SavedState createFromParcel(Parcel in, ClassLoader loader) {
                return new SavedState(in, loader);
            }

            @Override // android.os.Parcelable.Creator
            public SavedState createFromParcel(Parcel in) {
                return new SavedState(in, (ClassLoader) null);
            }

            @Override // android.os.Parcelable.Creator
            public SavedState[] newArray(int size) {
                return new SavedState[size];
            }
        };
        final int state;

        public SavedState(Parcel source) {
            this(source, (ClassLoader) null);
        }

        public SavedState(Parcel source, ClassLoader loader) {
            super(source, loader);
            this.state = source.readInt();
        }

        public SavedState(Parcelable superState, SideSheetBehavior<?> behavior) {
            super(superState);
            this.state = ((SideSheetBehavior) behavior).state;
        }

        @Override // androidx.customview.view.AbsSavedState, android.os.Parcelable
        public void writeToParcel(Parcel out, int flags) {
            super.writeToParcel(out, flags);
            out.writeInt(this.state);
        }
    }

    public static <V extends View> SideSheetBehavior<V> from(V view) {
        ViewGroup.LayoutParams params = view.getLayoutParams();
        if (!(params instanceof CoordinatorLayout.LayoutParams)) {
            throw new IllegalArgumentException("The view is not a child of CoordinatorLayout");
        }
        CoordinatorLayout.Behavior<?> behavior = ((CoordinatorLayout.LayoutParams) params).getBehavior();
        if (!(behavior instanceof SideSheetBehavior)) {
            throw new IllegalArgumentException("The view is not associated with SideSheetBehavior");
        }
        return (SideSheetBehavior) behavior;
    }

    private void updateAccessibilityActions() {
        V child;
        if (this.viewRef == null || (child = this.viewRef.get()) == null) {
            return;
        }
        ViewCompat.removeAccessibilityAction(child, 262144);
        ViewCompat.removeAccessibilityAction(child, 1048576);
        if (this.state != 5) {
            replaceAccessibilityActionForState(child, AccessibilityNodeInfoCompat.AccessibilityActionCompat.ACTION_DISMISS, 5);
        }
        if (this.state != 3) {
            replaceAccessibilityActionForState(child, AccessibilityNodeInfoCompat.AccessibilityActionCompat.ACTION_EXPAND, 3);
        }
    }

    private void replaceAccessibilityActionForState(V child, AccessibilityNodeInfoCompat.AccessibilityActionCompat action, int state) {
        ViewCompat.replaceAccessibilityAction(child, action, null, createAccessibilityViewCommandForState(state));
    }

    private AccessibilityViewCommand createAccessibilityViewCommandForState(final int state) {
        return new AccessibilityViewCommand() { // from class: com.google.android.material.sidesheet.SideSheetBehavior$$ExternalSyntheticLambda2
            @Override // androidx.core.view.accessibility.AccessibilityViewCommand
            public final boolean perform(View view, AccessibilityViewCommand.CommandArguments commandArguments) {
                return SideSheetBehavior.this.m120x564aa398(state, view, commandArguments);
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$createAccessibilityViewCommandForState$2$com-google-android-material-sidesheet-SideSheetBehavior  reason: not valid java name */
    public /* synthetic */ boolean m120x564aa398(int state, View view, AccessibilityViewCommand.CommandArguments arguments) {
        setState(state);
        return true;
    }
}
