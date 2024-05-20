package com.google.android.material.search;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.TimeInterpolator;
import android.animation.ValueAnimator;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.view.Menu;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.TextView;
import androidx.activity.BackEventCompat;
import androidx.appcompat.graphics.drawable.DrawerArrowDrawable;
import androidx.appcompat.widget.ActionMenuView;
import androidx.appcompat.widget.Toolbar;
import androidx.core.graphics.drawable.DrawableCompat;
import androidx.core.view.MarginLayoutParamsCompat;
import androidx.core.view.ViewCompat;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.internal.ClippableRoundedCornerLayout;
import com.google.android.material.internal.FadeThroughDrawable;
import com.google.android.material.internal.FadeThroughUpdateListener;
import com.google.android.material.internal.MultiViewUpdateListener;
import com.google.android.material.internal.RectEvaluator;
import com.google.android.material.internal.ReversableAnimatedValueInterpolator;
import com.google.android.material.internal.ToolbarUtils;
import com.google.android.material.internal.TouchObserverFrameLayout;
import com.google.android.material.internal.ViewUtils;
import com.google.android.material.motion.MaterialMainContainerBackHelper;
import com.google.android.material.search.SearchView;
import java.util.Objects;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class SearchViewAnimationHelper {
    private static final float CONTENT_FROM_SCALE = 0.95f;
    private static final long HIDE_CLEAR_BUTTON_ALPHA_DURATION_MS = 42;
    private static final long HIDE_CLEAR_BUTTON_ALPHA_START_DELAY_MS = 0;
    private static final long HIDE_CONTENT_ALPHA_DURATION_MS = 83;
    private static final long HIDE_CONTENT_ALPHA_START_DELAY_MS = 0;
    private static final long HIDE_CONTENT_SCALE_DURATION_MS = 250;
    private static final long HIDE_DURATION_MS = 250;
    private static final long HIDE_TRANSLATE_DURATION_MS = 300;
    private static final long SHOW_CLEAR_BUTTON_ALPHA_DURATION_MS = 50;
    private static final long SHOW_CLEAR_BUTTON_ALPHA_START_DELAY_MS = 250;
    private static final long SHOW_CONTENT_ALPHA_DURATION_MS = 150;
    private static final long SHOW_CONTENT_ALPHA_START_DELAY_MS = 75;
    private static final long SHOW_CONTENT_SCALE_DURATION_MS = 300;
    private static final long SHOW_DURATION_MS = 300;
    private static final long SHOW_TRANSLATE_DURATION_MS = 350;
    private static final long SHOW_TRANSLATE_KEYBOARD_START_DELAY_MS = 150;
    private final MaterialMainContainerBackHelper backHelper;
    private AnimatorSet backProgressAnimatorSet;
    private final ImageButton clearButton;
    private final TouchObserverFrameLayout contentContainer;
    private final View divider;
    private final Toolbar dummyToolbar;
    private final EditText editText;
    private final FrameLayout headerContainer;
    private final ClippableRoundedCornerLayout rootView;
    private final View scrim;
    private SearchBar searchBar;
    private final TextView searchPrefix;
    private final SearchView searchView;
    private final Toolbar toolbar;
    private final FrameLayout toolbarContainer;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SearchViewAnimationHelper(SearchView searchView) {
        this.searchView = searchView;
        this.scrim = searchView.scrim;
        this.rootView = searchView.rootView;
        this.headerContainer = searchView.headerContainer;
        this.toolbarContainer = searchView.toolbarContainer;
        this.toolbar = searchView.toolbar;
        this.dummyToolbar = searchView.dummyToolbar;
        this.searchPrefix = searchView.searchPrefix;
        this.editText = searchView.editText;
        this.clearButton = searchView.clearButton;
        this.divider = searchView.divider;
        this.contentContainer = searchView.contentContainer;
        this.backHelper = new MaterialMainContainerBackHelper(this.rootView);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setSearchBar(SearchBar searchBar) {
        this.searchBar = searchBar;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void show() {
        if (this.searchBar != null) {
            startShowAnimationExpand();
        } else {
            startShowAnimationTranslate();
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public AnimatorSet hide() {
        if (this.searchBar != null) {
            return startHideAnimationCollapse();
        }
        return startHideAnimationTranslate();
    }

    private void startShowAnimationExpand() {
        if (this.searchView.isAdjustNothingSoftInputMode()) {
            this.searchView.requestFocusAndShowKeyboardIfNeeded();
        }
        this.searchView.setTransitionState(SearchView.TransitionState.SHOWING);
        setUpDummyToolbarIfNeeded();
        this.editText.setText(this.searchBar.getText());
        this.editText.setSelection(this.editText.getText().length());
        this.rootView.setVisibility(4);
        this.rootView.post(new Runnable() { // from class: com.google.android.material.search.SearchViewAnimationHelper$$ExternalSyntheticLambda2
            @Override // java.lang.Runnable
            public final void run() {
                SearchViewAnimationHelper.this.m117x94743afc();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$startShowAnimationExpand$0$com-google-android-material-search-SearchViewAnimationHelper  reason: not valid java name */
    public /* synthetic */ void m117x94743afc() {
        AnimatorSet animatorSet = getExpandCollapseAnimatorSet(true);
        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: com.google.android.material.search.SearchViewAnimationHelper.1
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationStart(Animator animation) {
                SearchViewAnimationHelper.this.rootView.setVisibility(0);
                SearchViewAnimationHelper.this.searchBar.stopOnLoadAnimation();
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (!SearchViewAnimationHelper.this.searchView.isAdjustNothingSoftInputMode()) {
                    SearchViewAnimationHelper.this.searchView.requestFocusAndShowKeyboardIfNeeded();
                }
                SearchViewAnimationHelper.this.searchView.setTransitionState(SearchView.TransitionState.SHOWN);
            }
        });
        animatorSet.start();
    }

    private AnimatorSet startHideAnimationCollapse() {
        if (this.searchView.isAdjustNothingSoftInputMode()) {
            this.searchView.clearFocusAndHideKeyboard();
        }
        AnimatorSet animatorSet = getExpandCollapseAnimatorSet(false);
        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: com.google.android.material.search.SearchViewAnimationHelper.2
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationStart(Animator animation) {
                SearchViewAnimationHelper.this.searchView.setTransitionState(SearchView.TransitionState.HIDING);
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                SearchViewAnimationHelper.this.rootView.setVisibility(8);
                if (!SearchViewAnimationHelper.this.searchView.isAdjustNothingSoftInputMode()) {
                    SearchViewAnimationHelper.this.searchView.clearFocusAndHideKeyboard();
                }
                SearchViewAnimationHelper.this.searchView.setTransitionState(SearchView.TransitionState.HIDDEN);
            }
        });
        animatorSet.start();
        return animatorSet;
    }

    private void startShowAnimationTranslate() {
        if (this.searchView.isAdjustNothingSoftInputMode()) {
            SearchView searchView = this.searchView;
            final SearchView searchView2 = this.searchView;
            Objects.requireNonNull(searchView2);
            searchView.postDelayed(new Runnable() { // from class: com.google.android.material.search.SearchViewAnimationHelper$$ExternalSyntheticLambda3
                @Override // java.lang.Runnable
                public final void run() {
                    SearchView.this.requestFocusAndShowKeyboardIfNeeded();
                }
            }, 150L);
        }
        this.rootView.setVisibility(4);
        this.rootView.post(new Runnable() { // from class: com.google.android.material.search.SearchViewAnimationHelper$$ExternalSyntheticLambda4
            @Override // java.lang.Runnable
            public final void run() {
                SearchViewAnimationHelper.this.m118x4df249eb();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$startShowAnimationTranslate$1$com-google-android-material-search-SearchViewAnimationHelper  reason: not valid java name */
    public /* synthetic */ void m118x4df249eb() {
        this.rootView.setTranslationY(this.rootView.getHeight());
        AnimatorSet animatorSet = getTranslateAnimatorSet(true);
        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: com.google.android.material.search.SearchViewAnimationHelper.3
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationStart(Animator animation) {
                SearchViewAnimationHelper.this.rootView.setVisibility(0);
                SearchViewAnimationHelper.this.searchView.setTransitionState(SearchView.TransitionState.SHOWING);
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (!SearchViewAnimationHelper.this.searchView.isAdjustNothingSoftInputMode()) {
                    SearchViewAnimationHelper.this.searchView.requestFocusAndShowKeyboardIfNeeded();
                }
                SearchViewAnimationHelper.this.searchView.setTransitionState(SearchView.TransitionState.SHOWN);
            }
        });
        animatorSet.start();
    }

    private AnimatorSet startHideAnimationTranslate() {
        if (this.searchView.isAdjustNothingSoftInputMode()) {
            this.searchView.clearFocusAndHideKeyboard();
        }
        AnimatorSet animatorSet = getTranslateAnimatorSet(false);
        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: com.google.android.material.search.SearchViewAnimationHelper.4
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationStart(Animator animation) {
                SearchViewAnimationHelper.this.searchView.setTransitionState(SearchView.TransitionState.HIDING);
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                SearchViewAnimationHelper.this.rootView.setVisibility(8);
                if (!SearchViewAnimationHelper.this.searchView.isAdjustNothingSoftInputMode()) {
                    SearchViewAnimationHelper.this.searchView.clearFocusAndHideKeyboard();
                }
                SearchViewAnimationHelper.this.searchView.setTransitionState(SearchView.TransitionState.HIDDEN);
            }
        });
        animatorSet.start();
        return animatorSet;
    }

    private AnimatorSet getTranslateAnimatorSet(boolean show) {
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(getTranslationYAnimator());
        addBackButtonProgressAnimatorIfNeeded(animatorSet);
        animatorSet.setInterpolator(ReversableAnimatedValueInterpolator.of(show, AnimationUtils.FAST_OUT_SLOW_IN_INTERPOLATOR));
        animatorSet.setDuration(show ? SHOW_TRANSLATE_DURATION_MS : 300L);
        return animatorSet;
    }

    private Animator getTranslationYAnimator() {
        ValueAnimator animator = ValueAnimator.ofFloat(this.rootView.getHeight(), 0.0f);
        animator.addUpdateListener(MultiViewUpdateListener.translationYListener(this.rootView));
        return animator;
    }

    private AnimatorSet getExpandCollapseAnimatorSet(final boolean show) {
        AnimatorSet animatorSet = new AnimatorSet();
        boolean backProgress = this.backProgressAnimatorSet != null;
        if (!backProgress) {
            animatorSet.playTogether(getButtonsProgressAnimator(show), getButtonsTranslationAnimator(show));
        }
        animatorSet.playTogether(getScrimAlphaAnimator(show), getRootViewAnimator(show), getClearButtonAnimator(show), getContentAnimator(show), getHeaderContainerAnimator(show), getDummyToolbarAnimator(show), getActionMenuViewsAlphaAnimator(show), getEditTextAnimator(show), getSearchPrefixAnimator(show));
        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: com.google.android.material.search.SearchViewAnimationHelper.5
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationStart(Animator animation) {
                SearchViewAnimationHelper.this.setContentViewsAlpha(show ? 0.0f : 1.0f);
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                SearchViewAnimationHelper.this.setContentViewsAlpha(show ? 1.0f : 0.0f);
                SearchViewAnimationHelper.this.rootView.resetClipBoundsAndCornerRadius();
            }
        });
        return animatorSet;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setContentViewsAlpha(float alpha) {
        this.clearButton.setAlpha(alpha);
        this.divider.setAlpha(alpha);
        this.contentContainer.setAlpha(alpha);
        setActionMenuViewAlphaIfNeeded(alpha);
    }

    private void setActionMenuViewAlphaIfNeeded(float alpha) {
        ActionMenuView actionMenuView;
        if (this.searchView.isMenuItemsAnimated() && (actionMenuView = ToolbarUtils.getActionMenuView(this.toolbar)) != null) {
            actionMenuView.setAlpha(alpha);
        }
    }

    private Animator getScrimAlphaAnimator(boolean show) {
        TimeInterpolator interpolator = show ? AnimationUtils.LINEAR_INTERPOLATOR : AnimationUtils.FAST_OUT_SLOW_IN_INTERPOLATOR;
        ValueAnimator animator = ValueAnimator.ofFloat(0.0f, 1.0f);
        animator.setDuration(show ? 300L : 250L);
        animator.setInterpolator(ReversableAnimatedValueInterpolator.of(show, interpolator));
        animator.addUpdateListener(MultiViewUpdateListener.alphaListener(this.scrim));
        return animator;
    }

    private Animator getRootViewAnimator(boolean show) {
        Rect toClipBounds;
        Rect fromClipBounds;
        Rect initialHideToClipBounds = this.backHelper.getInitialHideToClipBounds();
        Rect initialHideFromClipBounds = this.backHelper.getInitialHideFromClipBounds();
        if (initialHideToClipBounds != null) {
            toClipBounds = initialHideToClipBounds;
        } else {
            toClipBounds = ViewUtils.calculateRectFromBounds(this.searchView);
        }
        if (initialHideFromClipBounds != null) {
            fromClipBounds = initialHideFromClipBounds;
        } else {
            fromClipBounds = ViewUtils.calculateOffsetRectFromBounds(this.rootView, this.searchBar);
        }
        final Rect clipBounds = new Rect(fromClipBounds);
        final float fromCornerRadius = this.searchBar.getCornerSize();
        final float toCornerRadius = Math.max(this.rootView.getCornerRadius(), this.backHelper.getExpandedCornerSize());
        ValueAnimator animator = ValueAnimator.ofObject(new RectEvaluator(clipBounds), fromClipBounds, toClipBounds);
        animator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: com.google.android.material.search.SearchViewAnimationHelper$$ExternalSyntheticLambda5
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                SearchViewAnimationHelper.this.m116xa183b80f(fromCornerRadius, toCornerRadius, clipBounds, valueAnimator);
            }
        });
        animator.setDuration(show ? 300L : 250L);
        animator.setInterpolator(ReversableAnimatedValueInterpolator.of(show, AnimationUtils.FAST_OUT_SLOW_IN_INTERPOLATOR));
        return animator;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$getRootViewAnimator$2$com-google-android-material-search-SearchViewAnimationHelper  reason: not valid java name */
    public /* synthetic */ void m116xa183b80f(float fromCornerRadius, float toCornerRadius, Rect clipBounds, ValueAnimator valueAnimator) {
        float cornerRadius = AnimationUtils.lerp(fromCornerRadius, toCornerRadius, valueAnimator.getAnimatedFraction());
        this.rootView.updateClipBoundsAndCornerRadius(clipBounds, cornerRadius);
    }

    private Animator getClearButtonAnimator(boolean show) {
        ValueAnimator animator = ValueAnimator.ofFloat(0.0f, 1.0f);
        animator.setDuration(show ? SHOW_CLEAR_BUTTON_ALPHA_DURATION_MS : HIDE_CLEAR_BUTTON_ALPHA_DURATION_MS);
        animator.setStartDelay(show ? 250L : 0L);
        animator.setInterpolator(ReversableAnimatedValueInterpolator.of(show, AnimationUtils.LINEAR_INTERPOLATOR));
        animator.addUpdateListener(MultiViewUpdateListener.alphaListener(this.clearButton));
        return animator;
    }

    private AnimatorSet getButtonsProgressAnimator(boolean show) {
        AnimatorSet animatorSet = new AnimatorSet();
        addBackButtonProgressAnimatorIfNeeded(animatorSet);
        animatorSet.setDuration(show ? 300L : 250L);
        animatorSet.setInterpolator(ReversableAnimatedValueInterpolator.of(show, AnimationUtils.FAST_OUT_SLOW_IN_INTERPOLATOR));
        return animatorSet;
    }

    private AnimatorSet getButtonsTranslationAnimator(boolean show) {
        AnimatorSet animatorSet = new AnimatorSet();
        addBackButtonTranslationAnimatorIfNeeded(animatorSet);
        addActionMenuViewAnimatorIfNeeded(animatorSet);
        animatorSet.setDuration(show ? 300L : 250L);
        animatorSet.setInterpolator(ReversableAnimatedValueInterpolator.of(show, AnimationUtils.FAST_OUT_SLOW_IN_INTERPOLATOR));
        return animatorSet;
    }

    private void addBackButtonTranslationAnimatorIfNeeded(AnimatorSet animatorSet) {
        ImageButton backButton = ToolbarUtils.getNavigationIconButton(this.toolbar);
        if (backButton == null) {
            return;
        }
        ValueAnimator backButtonAnimatorX = ValueAnimator.ofFloat(getFromTranslationXStart(backButton), 0.0f);
        backButtonAnimatorX.addUpdateListener(MultiViewUpdateListener.translationXListener(backButton));
        ValueAnimator backButtonAnimatorY = ValueAnimator.ofFloat(getFromTranslationY(), 0.0f);
        backButtonAnimatorY.addUpdateListener(MultiViewUpdateListener.translationYListener(backButton));
        animatorSet.playTogether(backButtonAnimatorX, backButtonAnimatorY);
    }

    private void addBackButtonProgressAnimatorIfNeeded(AnimatorSet animatorSet) {
        ImageButton backButton = ToolbarUtils.getNavigationIconButton(this.toolbar);
        if (backButton == null) {
            return;
        }
        Drawable drawable = DrawableCompat.unwrap(backButton.getDrawable());
        if (this.searchView.isAnimatedNavigationIcon()) {
            addDrawerArrowDrawableAnimatorIfNeeded(animatorSet, drawable);
            addFadeThroughDrawableAnimatorIfNeeded(animatorSet, drawable);
            return;
        }
        setFullDrawableProgressIfNeeded(drawable);
    }

    private void addDrawerArrowDrawableAnimatorIfNeeded(AnimatorSet animatorSet, Drawable drawable) {
        if (drawable instanceof DrawerArrowDrawable) {
            final DrawerArrowDrawable drawerArrowDrawable = (DrawerArrowDrawable) drawable;
            ValueAnimator animator = ValueAnimator.ofFloat(0.0f, 1.0f);
            animator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: com.google.android.material.search.SearchViewAnimationHelper$$ExternalSyntheticLambda1
                @Override // android.animation.ValueAnimator.AnimatorUpdateListener
                public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                    DrawerArrowDrawable.this.setProgress(((Float) valueAnimator.getAnimatedValue()).floatValue());
                }
            });
            animatorSet.playTogether(animator);
        }
    }

    private void addFadeThroughDrawableAnimatorIfNeeded(AnimatorSet animatorSet, Drawable drawable) {
        if (drawable instanceof FadeThroughDrawable) {
            final FadeThroughDrawable fadeThroughDrawable = (FadeThroughDrawable) drawable;
            ValueAnimator animator = ValueAnimator.ofFloat(0.0f, 1.0f);
            animator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: com.google.android.material.search.SearchViewAnimationHelper$$ExternalSyntheticLambda0
                @Override // android.animation.ValueAnimator.AnimatorUpdateListener
                public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                    FadeThroughDrawable.this.setProgress(((Float) valueAnimator.getAnimatedValue()).floatValue());
                }
            });
            animatorSet.playTogether(animator);
        }
    }

    private void setFullDrawableProgressIfNeeded(Drawable drawable) {
        if (drawable instanceof DrawerArrowDrawable) {
            ((DrawerArrowDrawable) drawable).setProgress(1.0f);
        }
        if (drawable instanceof FadeThroughDrawable) {
            ((FadeThroughDrawable) drawable).setProgress(1.0f);
        }
    }

    private void addActionMenuViewAnimatorIfNeeded(AnimatorSet animatorSet) {
        ActionMenuView actionMenuView = ToolbarUtils.getActionMenuView(this.toolbar);
        if (actionMenuView == null) {
            return;
        }
        ValueAnimator actionMenuViewAnimatorX = ValueAnimator.ofFloat(getFromTranslationXEnd(actionMenuView), 0.0f);
        actionMenuViewAnimatorX.addUpdateListener(MultiViewUpdateListener.translationXListener(actionMenuView));
        ValueAnimator actionMenuViewAnimatorY = ValueAnimator.ofFloat(getFromTranslationY(), 0.0f);
        actionMenuViewAnimatorY.addUpdateListener(MultiViewUpdateListener.translationYListener(actionMenuView));
        animatorSet.playTogether(actionMenuViewAnimatorX, actionMenuViewAnimatorY);
    }

    private Animator getDummyToolbarAnimator(boolean show) {
        return getTranslationAnimator(show, false, this.dummyToolbar);
    }

    private Animator getHeaderContainerAnimator(boolean show) {
        return getTranslationAnimator(show, false, this.headerContainer);
    }

    private Animator getActionMenuViewsAlphaAnimator(boolean show) {
        ValueAnimator animator = ValueAnimator.ofFloat(0.0f, 1.0f);
        animator.setDuration(show ? 300L : 250L);
        animator.setInterpolator(ReversableAnimatedValueInterpolator.of(show, AnimationUtils.FAST_OUT_SLOW_IN_INTERPOLATOR));
        if (this.searchView.isMenuItemsAnimated()) {
            ActionMenuView dummyActionMenuView = ToolbarUtils.getActionMenuView(this.dummyToolbar);
            ActionMenuView actionMenuView = ToolbarUtils.getActionMenuView(this.toolbar);
            animator.addUpdateListener(new FadeThroughUpdateListener(dummyActionMenuView, actionMenuView));
        }
        return animator;
    }

    private Animator getSearchPrefixAnimator(boolean show) {
        return getTranslationAnimator(show, true, this.searchPrefix);
    }

    private Animator getEditTextAnimator(boolean show) {
        return getTranslationAnimator(show, true, this.editText);
    }

    private Animator getContentAnimator(boolean show) {
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(getContentAlphaAnimator(show), getDividerAnimator(show), getContentScaleAnimator(show));
        return animatorSet;
    }

    private Animator getContentAlphaAnimator(boolean show) {
        ValueAnimator animatorAlpha = ValueAnimator.ofFloat(0.0f, 1.0f);
        animatorAlpha.setDuration(show ? 150L : HIDE_CONTENT_ALPHA_DURATION_MS);
        animatorAlpha.setStartDelay(show ? 75L : 0L);
        animatorAlpha.setInterpolator(ReversableAnimatedValueInterpolator.of(show, AnimationUtils.LINEAR_INTERPOLATOR));
        animatorAlpha.addUpdateListener(MultiViewUpdateListener.alphaListener(this.divider, this.contentContainer));
        return animatorAlpha;
    }

    private Animator getDividerAnimator(boolean show) {
        float dividerTranslationY = (this.contentContainer.getHeight() * 0.050000012f) / 2.0f;
        ValueAnimator animatorDivider = ValueAnimator.ofFloat(dividerTranslationY, 0.0f);
        animatorDivider.setDuration(show ? 300L : 250L);
        animatorDivider.setInterpolator(ReversableAnimatedValueInterpolator.of(show, AnimationUtils.FAST_OUT_SLOW_IN_INTERPOLATOR));
        animatorDivider.addUpdateListener(MultiViewUpdateListener.translationYListener(this.divider));
        return animatorDivider;
    }

    private Animator getContentScaleAnimator(boolean show) {
        ValueAnimator animatorScale = ValueAnimator.ofFloat(CONTENT_FROM_SCALE, 1.0f);
        animatorScale.setDuration(show ? 300L : 250L);
        animatorScale.setInterpolator(ReversableAnimatedValueInterpolator.of(show, AnimationUtils.FAST_OUT_SLOW_IN_INTERPOLATOR));
        animatorScale.addUpdateListener(MultiViewUpdateListener.scaleListener(this.contentContainer));
        return animatorScale;
    }

    private Animator getTranslationAnimator(boolean show, boolean anchoredToStart, View view) {
        int startX = anchoredToStart ? getFromTranslationXStart(view) : getFromTranslationXEnd(view);
        ValueAnimator animatorX = ValueAnimator.ofFloat(startX, 0.0f);
        animatorX.addUpdateListener(MultiViewUpdateListener.translationXListener(view));
        ValueAnimator animatorY = ValueAnimator.ofFloat(getFromTranslationY(), 0.0f);
        animatorY.addUpdateListener(MultiViewUpdateListener.translationYListener(view));
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(animatorX, animatorY);
        animatorSet.setDuration(show ? 300L : 250L);
        animatorSet.setInterpolator(ReversableAnimatedValueInterpolator.of(show, AnimationUtils.FAST_OUT_SLOW_IN_INTERPOLATOR));
        return animatorSet;
    }

    private int getFromTranslationXStart(View view) {
        int marginStart = MarginLayoutParamsCompat.getMarginStart((ViewGroup.MarginLayoutParams) view.getLayoutParams());
        int paddingStart = ViewCompat.getPaddingStart(this.searchBar);
        if (ViewUtils.isLayoutRtl(this.searchBar)) {
            return ((this.searchBar.getWidth() - this.searchBar.getRight()) + marginStart) - paddingStart;
        }
        return (this.searchBar.getLeft() - marginStart) + paddingStart;
    }

    private int getFromTranslationXEnd(View view) {
        int marginEnd = MarginLayoutParamsCompat.getMarginEnd((ViewGroup.MarginLayoutParams) view.getLayoutParams());
        if (ViewUtils.isLayoutRtl(this.searchBar)) {
            return this.searchBar.getLeft() - marginEnd;
        }
        return (this.searchBar.getRight() - this.searchView.getWidth()) + marginEnd;
    }

    private int getFromTranslationY() {
        int toolbarMiddleY = (this.toolbarContainer.getTop() + this.toolbarContainer.getBottom()) / 2;
        int searchBarMiddleY = (this.searchBar.getTop() + this.searchBar.getBottom()) / 2;
        return searchBarMiddleY - toolbarMiddleY;
    }

    private void setUpDummyToolbarIfNeeded() {
        Menu menu = this.dummyToolbar.getMenu();
        if (menu != null) {
            menu.clear();
        }
        if (this.searchBar.getMenuResId() != -1 && this.searchView.isMenuItemsAnimated()) {
            this.dummyToolbar.inflateMenu(this.searchBar.getMenuResId());
            setMenuItemsNotClickable(this.dummyToolbar);
            this.dummyToolbar.setVisibility(0);
            return;
        }
        this.dummyToolbar.setVisibility(8);
    }

    private void setMenuItemsNotClickable(Toolbar toolbar) {
        ActionMenuView actionMenuView = ToolbarUtils.getActionMenuView(toolbar);
        if (actionMenuView != null) {
            for (int i = 0; i < actionMenuView.getChildCount(); i++) {
                View menuItem = actionMenuView.getChildAt(i);
                menuItem.setClickable(false);
                menuItem.setFocusable(false);
                menuItem.setFocusableInTouchMode(false);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void startBackProgress(BackEventCompat backEvent) {
        this.backHelper.startBackProgress(backEvent, this.searchBar);
    }

    public void updateBackProgress(BackEventCompat backEvent) {
        if (backEvent.getProgress() <= 0.0f) {
            return;
        }
        this.backHelper.updateBackProgress(backEvent, this.searchBar, this.searchBar.getCornerSize());
        if (this.backProgressAnimatorSet == null) {
            if (this.searchView.isAdjustNothingSoftInputMode()) {
                this.searchView.clearFocusAndHideKeyboard();
            }
            if (!this.searchView.isAnimatedNavigationIcon()) {
                return;
            }
            this.backProgressAnimatorSet = getButtonsProgressAnimator(false);
            this.backProgressAnimatorSet.start();
            this.backProgressAnimatorSet.pause();
            return;
        }
        this.backProgressAnimatorSet.setCurrentPlayTime(backEvent.getProgress() * ((float) this.backProgressAnimatorSet.getDuration()));
    }

    public BackEventCompat onHandleBackInvoked() {
        return this.backHelper.onHandleBackInvoked();
    }

    public void finishBackProgress() {
        AnimatorSet hideAnimatorSet = hide();
        long totalDuration = hideAnimatorSet.getTotalDuration();
        this.backHelper.finishBackProgress(totalDuration, this.searchBar);
        if (this.backProgressAnimatorSet != null) {
            getButtonsTranslationAnimator(false).start();
            this.backProgressAnimatorSet.resume();
        }
        this.backProgressAnimatorSet = null;
    }

    public void cancelBackProgress() {
        this.backHelper.cancelBackProgress(this.searchBar);
        if (this.backProgressAnimatorSet != null) {
            this.backProgressAnimatorSet.reverse();
        }
        this.backProgressAnimatorSet = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MaterialMainContainerBackHelper getBackHelper() {
        return this.backHelper;
    }
}
