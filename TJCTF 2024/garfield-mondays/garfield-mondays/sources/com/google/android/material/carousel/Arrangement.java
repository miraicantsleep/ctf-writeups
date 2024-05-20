package com.google.android.material.carousel;

import androidx.core.math.MathUtils;
/* loaded from: classes.dex */
final class Arrangement {
    private static final float MEDIUM_ITEM_FLEX_PERCENTAGE = 0.1f;
    final float cost;
    final int largeCount;
    float largeSize;
    int mediumCount;
    float mediumSize;
    final int priority;
    int smallCount;
    float smallSize;

    /* JADX INFO: Access modifiers changed from: package-private */
    public Arrangement(int priority, float targetSmallSize, float minSmallSize, float maxSmallSize, int smallCount, float targetMediumSize, int mediumCount, float targetLargeSize, int largeCount, float availableSpace) {
        this.priority = priority;
        this.smallSize = MathUtils.clamp(targetSmallSize, minSmallSize, maxSmallSize);
        this.smallCount = smallCount;
        this.mediumSize = targetMediumSize;
        this.mediumCount = mediumCount;
        this.largeSize = targetLargeSize;
        this.largeCount = largeCount;
        fit(availableSpace, minSmallSize, maxSmallSize, targetLargeSize);
        this.cost = cost(targetLargeSize);
    }

    public String toString() {
        return "Arrangement [priority=" + this.priority + ", smallCount=" + this.smallCount + ", smallSize=" + this.smallSize + ", mediumCount=" + this.mediumCount + ", mediumSize=" + this.mediumSize + ", largeCount=" + this.largeCount + ", largeSize=" + this.largeSize + ", cost=" + this.cost + "]";
    }

    private float getSpace() {
        return (this.largeSize * this.largeCount) + (this.mediumSize * this.mediumCount) + (this.smallSize * this.smallCount);
    }

    private void fit(float availableSpace, float minSmallSize, float maxSmallSize, float targetLargeSize) {
        float delta = availableSpace - getSpace();
        if (this.smallCount > 0 && delta > 0.0f) {
            this.smallSize += Math.min(delta / this.smallCount, maxSmallSize - this.smallSize);
        } else if (this.smallCount > 0 && delta < 0.0f) {
            this.smallSize += Math.max(delta / this.smallCount, minSmallSize - this.smallSize);
        }
        this.smallSize = this.smallCount > 0 ? this.smallSize : 0.0f;
        this.largeSize = calculateLargeSize(availableSpace, this.smallCount, this.smallSize, this.mediumCount, this.largeCount);
        this.mediumSize = (this.largeSize + this.smallSize) / 2.0f;
        if (this.mediumCount > 0 && this.largeSize != targetLargeSize) {
            float targetAdjustment = (targetLargeSize - this.largeSize) * this.largeCount;
            float availableMediumFlex = this.mediumSize * 0.1f * this.mediumCount;
            float distribute = Math.min(Math.abs(targetAdjustment), availableMediumFlex);
            if (targetAdjustment > 0.0f) {
                this.mediumSize -= distribute / this.mediumCount;
                this.largeSize += distribute / this.largeCount;
                return;
            }
            this.mediumSize += distribute / this.mediumCount;
            this.largeSize -= distribute / this.largeCount;
        }
    }

    private float calculateLargeSize(float availableSpace, int smallCount, float smallSize, int mediumCount, int largeCount) {
        return (availableSpace - ((smallCount + (mediumCount / 2.0f)) * (smallCount > 0 ? smallSize : 0.0f))) / (largeCount + (mediumCount / 2.0f));
    }

    private boolean isValid() {
        return (this.largeCount <= 0 || this.smallCount <= 0 || this.mediumCount <= 0) ? this.largeCount <= 0 || this.smallCount <= 0 || this.largeSize > this.smallSize : this.largeSize > this.mediumSize && this.mediumSize > this.smallSize;
    }

    private float cost(float targetLargeSize) {
        if (!isValid()) {
            return Float.MAX_VALUE;
        }
        return Math.abs(targetLargeSize - this.largeSize) * this.priority;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Arrangement findLowestCostArrangement(float availableSpace, float targetSmallSize, float minSmallSize, float maxSmallSize, int[] smallCounts, float targetMediumSize, int[] mediumCounts, float targetLargeSize, int[] largeCounts) {
        Arrangement lowestCostArrangement = null;
        int priority = 1;
        for (int largeCount : largeCounts) {
            int length = mediumCounts.length;
            int i = 0;
            while (i < length) {
                int mediumCount = mediumCounts[i];
                int length2 = smallCounts.length;
                int i2 = 0;
                while (i2 < length2) {
                    int smallCount = smallCounts[i2];
                    int i3 = i2;
                    int i4 = length2;
                    int i5 = i;
                    int i6 = length;
                    Arrangement arrangement = new Arrangement(priority, targetSmallSize, minSmallSize, maxSmallSize, smallCount, targetMediumSize, mediumCount, targetLargeSize, largeCount, availableSpace);
                    if (lowestCostArrangement == null || arrangement.cost < lowestCostArrangement.cost) {
                        lowestCostArrangement = arrangement;
                        if (lowestCostArrangement.cost == 0.0f) {
                            return lowestCostArrangement;
                        }
                    }
                    priority++;
                    i2 = i3 + 1;
                    length2 = i4;
                    i = i5;
                    length = i6;
                }
                i++;
            }
        }
        return lowestCostArrangement;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getItemCount() {
        return this.smallCount + this.mediumCount + this.largeCount;
    }
}
