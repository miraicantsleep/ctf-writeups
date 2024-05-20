package com.google.android.material.carousel;

import androidx.core.math.MathUtils;
import com.google.android.material.animation.AnimationUtils;
import com.google.android.material.carousel.KeylineState;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class KeylineStateList {
    private static final int NO_INDEX = -1;
    private final KeylineState defaultState;
    private final float endShiftRange;
    private final List<KeylineState> endStateSteps;
    private final float[] endStateStepsInterpolationPoints;
    private final float startShiftRange;
    private final List<KeylineState> startStateSteps;
    private final float[] startStateStepsInterpolationPoints;

    private KeylineStateList(KeylineState defaultState, List<KeylineState> startStateSteps, List<KeylineState> endStateSteps) {
        this.defaultState = defaultState;
        this.startStateSteps = Collections.unmodifiableList(startStateSteps);
        this.endStateSteps = Collections.unmodifiableList(endStateSteps);
        this.startShiftRange = startStateSteps.get(startStateSteps.size() - 1).getFirstKeyline().loc - defaultState.getFirstKeyline().loc;
        this.endShiftRange = defaultState.getLastKeyline().loc - endStateSteps.get(endStateSteps.size() - 1).getLastKeyline().loc;
        this.startStateStepsInterpolationPoints = getStateStepInterpolationPoints(this.startShiftRange, startStateSteps, true);
        this.endStateStepsInterpolationPoints = getStateStepInterpolationPoints(this.endShiftRange, endStateSteps, false);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static KeylineStateList from(Carousel carousel, KeylineState state) {
        return new KeylineStateList(state, getStateStepsStart(carousel, state), getStateStepsEnd(carousel, state));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public KeylineState getDefaultState() {
        return this.defaultState;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public KeylineState getStartState() {
        return this.startStateSteps.get(this.startStateSteps.size() - 1);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public KeylineState getEndState() {
        return this.endStateSteps.get(this.endStateSteps.size() - 1);
    }

    public KeylineState getShiftedState(float scrollOffset, float minScrollOffset, float maxScrollOffset) {
        return getShiftedState(scrollOffset, minScrollOffset, maxScrollOffset, false);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public KeylineState getShiftedState(float scrollOffset, float minScrollOffset, float maxScrollOffset, boolean roundToNearestStep) {
        float interpolation;
        List<KeylineState> steps;
        float[] interpolationPoints;
        float startShiftOffset = this.startShiftRange + minScrollOffset;
        float endShiftOffset = maxScrollOffset - this.endShiftRange;
        if (scrollOffset < startShiftOffset) {
            interpolation = AnimationUtils.lerp(1.0f, 0.0f, minScrollOffset, startShiftOffset, scrollOffset);
            steps = this.startStateSteps;
            interpolationPoints = this.startStateStepsInterpolationPoints;
        } else if (scrollOffset > endShiftOffset) {
            interpolation = AnimationUtils.lerp(0.0f, 1.0f, endShiftOffset, maxScrollOffset, scrollOffset);
            steps = this.endStateSteps;
            interpolationPoints = this.endStateStepsInterpolationPoints;
        } else {
            return this.defaultState;
        }
        if (roundToNearestStep) {
            return closestStateStepFromInterpolation(steps, interpolation, interpolationPoints);
        }
        return lerp(steps, interpolation, interpolationPoints);
    }

    private static KeylineState lerp(List<KeylineState> stateSteps, float interpolation, float[] stateStepsInterpolationPoints) {
        float[] stateStepsRange = getStateStepsRange(stateSteps, interpolation, stateStepsInterpolationPoints);
        return KeylineState.lerp(stateSteps.get((int) stateStepsRange[1]), stateSteps.get((int) stateStepsRange[2]), stateStepsRange[0]);
    }

    private static float[] getStateStepsRange(List<KeylineState> stateSteps, float interpolation, float[] stateStepsInterpolationPoints) {
        int numberOfSteps = stateSteps.size();
        float lowerBounds = stateStepsInterpolationPoints[0];
        for (int i = 1; i < numberOfSteps; i++) {
            float upperBounds = stateStepsInterpolationPoints[i];
            if (interpolation <= upperBounds) {
                int fromIndex = i - 1;
                int toIndex = i;
                float steppedProgress = AnimationUtils.lerp(0.0f, 1.0f, lowerBounds, upperBounds, interpolation);
                return new float[]{steppedProgress, fromIndex, toIndex};
            }
            lowerBounds = upperBounds;
        }
        return new float[]{0.0f, 0.0f, 0.0f};
    }

    private KeylineState closestStateStepFromInterpolation(List<KeylineState> stateSteps, float interpolation, float[] stateStepsInterpolationPoints) {
        float[] stateStepsRange = getStateStepsRange(stateSteps, interpolation, stateStepsInterpolationPoints);
        if (stateStepsRange[0] > 0.5f) {
            return stateSteps.get((int) stateStepsRange[2]);
        }
        return stateSteps.get((int) stateStepsRange[1]);
    }

    private static float[] getStateStepInterpolationPoints(float shiftRange, List<KeylineState> stateSteps, boolean isShiftingLeft) {
        float distanceShifted;
        int numberOfSteps = stateSteps.size();
        float[] stateStepsInterpolationPoints = new float[numberOfSteps];
        int i = 1;
        while (i < numberOfSteps) {
            KeylineState prevState = stateSteps.get(i - 1);
            KeylineState currState = stateSteps.get(i);
            if (isShiftingLeft) {
                distanceShifted = currState.getFirstKeyline().loc - prevState.getFirstKeyline().loc;
            } else {
                distanceShifted = prevState.getLastKeyline().loc - currState.getLastKeyline().loc;
            }
            float stepProgress = distanceShifted / shiftRange;
            stateStepsInterpolationPoints[i] = i == numberOfSteps + (-1) ? 1.0f : stateStepsInterpolationPoints[i - 1] + stepProgress;
            i++;
        }
        return stateStepsInterpolationPoints;
    }

    private static boolean isFirstFocalItemAtLeftOfContainer(KeylineState state) {
        float firstFocalItemLeft = state.getFirstFocalKeyline().locOffset - (state.getFirstFocalKeyline().maskedItemSize / 2.0f);
        return firstFocalItemLeft >= 0.0f && state.getFirstFocalKeyline() == state.getFirstNonAnchorKeyline();
    }

    private static boolean isLastFocalItemVisibleAtRightOfContainer(Carousel carousel, KeylineState state) {
        int containerSize = carousel.getContainerHeight();
        if (carousel.isHorizontal()) {
            containerSize = carousel.getContainerWidth();
        }
        float lastFocalItemRight = state.getLastFocalKeyline().locOffset + (state.getLastFocalKeyline().maskedItemSize / 2.0f);
        return lastFocalItemRight <= ((float) containerSize) && state.getLastFocalKeyline() == state.getLastNonAnchorKeyline();
    }

    private static List<KeylineState> getStateStepsStart(Carousel carousel, KeylineState defaultState) {
        List<KeylineState> steps = new ArrayList<>();
        steps.add(defaultState);
        int firstNonAnchorKeylineIndex = findFirstNonAnchorKeylineIndex(defaultState);
        if (isFirstFocalItemAtLeftOfContainer(defaultState) || firstNonAnchorKeylineIndex == -1) {
            return steps;
        }
        int end = defaultState.getFirstFocalKeylineIndex();
        int numberOfSteps = end - firstNonAnchorKeylineIndex;
        float carouselSize = carousel.isHorizontal() ? carousel.getContainerWidth() : carousel.getContainerHeight();
        float originalStart = defaultState.getFirstKeyline().locOffset - (defaultState.getFirstKeyline().maskedItemSize / 2.0f);
        if (numberOfSteps <= 0 && defaultState.getFirstFocalKeyline().cutoff > 0.0f) {
            float cutoffs = defaultState.getFirstFocalKeyline().cutoff;
            steps.add(shiftKeylinesAndCreateKeylineState(defaultState, originalStart + cutoffs, carouselSize));
            return steps;
        }
        float cutoffs2 = 0.0f;
        int i = 0;
        while (i < numberOfSteps) {
            KeylineState prevStepState = steps.get(steps.size() - 1);
            int itemOrigIndex = firstNonAnchorKeylineIndex + i;
            int dstIndex = defaultState.getKeylines().size() - 1;
            float cutoffs3 = cutoffs2 + defaultState.getKeylines().get(itemOrigIndex).cutoff;
            if (itemOrigIndex - 1 >= 0) {
                float originalAdjacentMaskLeft = defaultState.getKeylines().get(itemOrigIndex - 1).mask;
                dstIndex = findFirstIndexAfterLastFocalKeylineWithMask(prevStepState, originalAdjacentMaskLeft) - 1;
            }
            int newFirstFocalIndex = (defaultState.getFirstFocalKeylineIndex() - i) - 1;
            int newLastFocalIndex = (defaultState.getLastFocalKeylineIndex() - i) - 1;
            KeylineState shifted = moveKeylineAndCreateKeylineState(prevStepState, firstNonAnchorKeylineIndex, dstIndex, originalStart + cutoffs3, newFirstFocalIndex, newLastFocalIndex, carouselSize);
            steps.add(shifted);
            i++;
            cutoffs2 = cutoffs3;
        }
        return steps;
    }

    private static List<KeylineState> getStateStepsEnd(Carousel carousel, KeylineState defaultState) {
        List<KeylineState> steps = new ArrayList<>();
        steps.add(defaultState);
        int lastNonAnchorKeylineIndex = findLastNonAnchorKeylineIndex(defaultState);
        if (isLastFocalItemVisibleAtRightOfContainer(carousel, defaultState) || lastNonAnchorKeylineIndex == -1) {
            return steps;
        }
        int start = defaultState.getLastFocalKeylineIndex();
        int numberOfSteps = lastNonAnchorKeylineIndex - start;
        float carouselSize = carousel.isHorizontal() ? carousel.getContainerWidth() : carousel.getContainerHeight();
        float originalStart = defaultState.getFirstKeyline().locOffset - (defaultState.getFirstKeyline().maskedItemSize / 2.0f);
        if (numberOfSteps <= 0 && defaultState.getLastFocalKeyline().cutoff > 0.0f) {
            float cutoffs = defaultState.getLastFocalKeyline().cutoff;
            steps.add(shiftKeylinesAndCreateKeylineState(defaultState, originalStart - cutoffs, carouselSize));
            return steps;
        }
        float cutoffs2 = 0.0f;
        int i = 0;
        while (i < numberOfSteps) {
            KeylineState prevStepState = steps.get(steps.size() - 1);
            int itemOrigIndex = lastNonAnchorKeylineIndex - i;
            float cutoffs3 = cutoffs2 + defaultState.getKeylines().get(itemOrigIndex).cutoff;
            int dstIndex = 0;
            if (itemOrigIndex + 1 < defaultState.getKeylines().size()) {
                float originalAdjacentMaskRight = defaultState.getKeylines().get(itemOrigIndex + 1).mask;
                dstIndex = findLastIndexBeforeFirstFocalKeylineWithMask(prevStepState, originalAdjacentMaskRight) + 1;
            }
            int dstIndex2 = dstIndex;
            int dstIndex3 = defaultState.getFirstFocalKeylineIndex();
            int newFirstFocalIndex = dstIndex3 + i + 1;
            int newLastFocalIndex = defaultState.getLastFocalKeylineIndex() + i + 1;
            KeylineState shifted = moveKeylineAndCreateKeylineState(prevStepState, lastNonAnchorKeylineIndex, dstIndex2, originalStart - cutoffs3, newFirstFocalIndex, newLastFocalIndex, carouselSize);
            steps.add(shifted);
            i++;
            cutoffs2 = cutoffs3;
        }
        return steps;
    }

    private static KeylineState shiftKeylinesAndCreateKeylineState(KeylineState state, float startOffset, float carouselSize) {
        return moveKeylineAndCreateKeylineState(state, 0, 0, startOffset, state.getFirstFocalKeylineIndex(), state.getLastFocalKeylineIndex(), carouselSize);
    }

    private static KeylineState moveKeylineAndCreateKeylineState(KeylineState state, int keylineSrcIndex, int keylineDstIndex, float startOffset, int newFirstFocalIndex, int newLastFocalIndex, float carouselSize) {
        boolean z;
        List<KeylineState.Keyline> tmpKeylines = new ArrayList<>(state.getKeylines());
        KeylineState.Keyline item = tmpKeylines.remove(keylineSrcIndex);
        tmpKeylines.add(keylineDstIndex, item);
        KeylineState.Builder builder = new KeylineState.Builder(state.getItemSize(), carouselSize);
        float startOffset2 = startOffset;
        int j = 0;
        while (j < tmpKeylines.size()) {
            KeylineState.Keyline k = (KeylineState.Keyline) tmpKeylines.get(j);
            float offset = startOffset2 + (k.maskedItemSize / 2.0f);
            if (j >= newFirstFocalIndex && j <= newLastFocalIndex) {
                z = true;
                boolean isFocal = z;
                builder.addKeyline(offset, k.mask, k.maskedItemSize, isFocal, k.isAnchor, k.cutoff);
                startOffset2 += k.maskedItemSize;
                j++;
                tmpKeylines = tmpKeylines;
            }
            z = false;
            boolean isFocal2 = z;
            builder.addKeyline(offset, k.mask, k.maskedItemSize, isFocal2, k.isAnchor, k.cutoff);
            startOffset2 += k.maskedItemSize;
            j++;
            tmpKeylines = tmpKeylines;
        }
        return builder.build();
    }

    private static int findFirstIndexAfterLastFocalKeylineWithMask(KeylineState state, float mask) {
        int focalEndIndex = state.getLastFocalKeylineIndex();
        for (int i = focalEndIndex; i < state.getKeylines().size(); i++) {
            if (mask == state.getKeylines().get(i).mask) {
                return i;
            }
        }
        return state.getKeylines().size() - 1;
    }

    private static int findLastIndexBeforeFirstFocalKeylineWithMask(KeylineState state, float mask) {
        int focalStartIndex = state.getFirstFocalKeylineIndex() - 1;
        for (int i = focalStartIndex; i >= 0; i--) {
            if (mask == state.getKeylines().get(i).mask) {
                return i;
            }
        }
        return 0;
    }

    private static int findFirstNonAnchorKeylineIndex(KeylineState state) {
        for (int i = 0; i < state.getKeylines().size(); i++) {
            if (!state.getKeylines().get(i).isAnchor) {
                return i;
            }
        }
        return -1;
    }

    private static int findLastNonAnchorKeylineIndex(KeylineState state) {
        for (int i = state.getKeylines().size() - 1; i >= 0; i--) {
            if (!state.getKeylines().get(i).isAnchor) {
                return i;
            }
        }
        return -1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Map<Integer, KeylineState> getKeylineStateForPositionMap(int itemCount, int minHorizontalScroll, int maxHorizontalScroll, boolean isRTL) {
        float itemSize = this.defaultState.getItemSize();
        Map<Integer, KeylineState> keylineStates = new HashMap<>();
        int endStepsIndex = 0;
        int startStepsIndex = 0;
        for (int i = 0; i < itemCount; i++) {
            int position = isRTL ? (itemCount - i) - 1 : i;
            float itemPosition = position * itemSize * (isRTL ? -1 : 1);
            if (itemPosition > maxHorizontalScroll - this.endShiftRange || i >= itemCount - this.endStateSteps.size()) {
                keylineStates.put(Integer.valueOf(position), this.endStateSteps.get(MathUtils.clamp(endStepsIndex, 0, this.endStateSteps.size() - 1)));
                endStepsIndex++;
            }
        }
        for (int i2 = itemCount - 1; i2 >= 0; i2--) {
            int position2 = isRTL ? (itemCount - i2) - 1 : i2;
            float itemPosition2 = position2 * itemSize * (isRTL ? -1 : 1);
            if (itemPosition2 < minHorizontalScroll + this.startShiftRange || i2 < this.startStateSteps.size()) {
                keylineStates.put(Integer.valueOf(position2), this.startStateSteps.get(MathUtils.clamp(startStepsIndex, 0, this.startStateSteps.size() - 1)));
                startStepsIndex++;
            }
        }
        return keylineStates;
    }
}
