package com.google.android.material.carousel;

import com.google.android.material.animation.AnimationUtils;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public final class KeylineState {
    private final int firstFocalKeylineIndex;
    private final float itemSize;
    private final List<Keyline> keylines;
    private final int lastFocalKeylineIndex;

    private KeylineState(float itemSize, List<Keyline> keylines, int firstFocalKeylineIndex, int lastFocalKeylineIndex) {
        this.itemSize = itemSize;
        this.keylines = Collections.unmodifiableList(keylines);
        this.firstFocalKeylineIndex = firstFocalKeylineIndex;
        this.lastFocalKeylineIndex = lastFocalKeylineIndex;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public float getItemSize() {
        return this.itemSize;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public List<Keyline> getKeylines() {
        return this.keylines;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Keyline getFirstFocalKeyline() {
        return this.keylines.get(this.firstFocalKeylineIndex);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getFirstFocalKeylineIndex() {
        return this.firstFocalKeylineIndex;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Keyline getLastFocalKeyline() {
        return this.keylines.get(this.lastFocalKeylineIndex);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getLastFocalKeylineIndex() {
        return this.lastFocalKeylineIndex;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public List<Keyline> getFocalKeylines() {
        return this.keylines.subList(this.firstFocalKeylineIndex, this.lastFocalKeylineIndex + 1);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Keyline getFirstKeyline() {
        return this.keylines.get(0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Keyline getLastKeyline() {
        return this.keylines.get(this.keylines.size() - 1);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Keyline getFirstNonAnchorKeyline() {
        for (int i = 0; i < this.keylines.size(); i++) {
            Keyline keyline = this.keylines.get(i);
            if (!keyline.isAnchor) {
                return keyline;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Keyline getLastNonAnchorKeyline() {
        for (int i = this.keylines.size() - 1; i >= 0; i--) {
            Keyline keyline = this.keylines.get(i);
            if (!keyline.isAnchor) {
                return keyline;
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static KeylineState lerp(KeylineState from, KeylineState to, float progress) {
        if (from.getItemSize() != to.getItemSize()) {
            throw new IllegalArgumentException("Keylines being linearly interpolated must have the same item size.");
        }
        List<Keyline> fromKeylines = from.getKeylines();
        List<Keyline> toKeylines = to.getKeylines();
        if (fromKeylines.size() != toKeylines.size()) {
            throw new IllegalArgumentException("Keylines being linearly interpolated must have the same number of keylines.");
        }
        List<Keyline> keylines = new ArrayList<>();
        for (int i = 0; i < from.getKeylines().size(); i++) {
            keylines.add(Keyline.lerp(fromKeylines.get(i), toKeylines.get(i), progress));
        }
        int focalKeylineFirstIndex = AnimationUtils.lerp(from.getFirstFocalKeylineIndex(), to.getFirstFocalKeylineIndex(), progress);
        int focalKeylineLastIndex = AnimationUtils.lerp(from.getLastFocalKeylineIndex(), to.getLastFocalKeylineIndex(), progress);
        return new KeylineState(from.getItemSize(), keylines, focalKeylineFirstIndex, focalKeylineLastIndex);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static KeylineState reverse(KeylineState keylineState, float availableSpace) {
        Builder builder = new Builder(keylineState.getItemSize(), availableSpace);
        float start = (availableSpace - keylineState.getLastKeyline().locOffset) - (keylineState.getLastKeyline().maskedItemSize / 2.0f);
        float start2 = start;
        int i = keylineState.getKeylines().size() - 1;
        while (i >= 0) {
            Keyline k = keylineState.getKeylines().get(i);
            float offset = start2 + (k.maskedItemSize / 2.0f);
            boolean isFocal = i >= keylineState.getFirstFocalKeylineIndex() && i <= keylineState.getLastFocalKeylineIndex();
            builder.addKeyline(offset, k.mask, k.maskedItemSize, isFocal, k.isAnchor);
            start2 += k.maskedItemSize;
            i--;
        }
        return builder.build();
    }

    /* loaded from: classes.dex */
    static final class Builder {
        private static final int NO_INDEX = -1;
        private static final float UNKNOWN_LOC = Float.MIN_VALUE;
        private final float availableSpace;
        private final float itemSize;
        private Keyline tmpFirstFocalKeyline;
        private Keyline tmpLastFocalKeyline;
        private final List<Keyline> tmpKeylines = new ArrayList();
        private int firstFocalKeylineIndex = -1;
        private int lastFocalKeylineIndex = -1;
        private float lastKeylineMaskedSize = 0.0f;
        private int latestAnchorKeylineIndex = -1;

        /* JADX INFO: Access modifiers changed from: package-private */
        public Builder(float itemSize, float availableSpace) {
            this.itemSize = itemSize;
            this.availableSpace = availableSpace;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public Builder addKeyline(float offsetLoc, float mask, float maskedItemSize, boolean isFocal) {
            return addKeyline(offsetLoc, mask, maskedItemSize, isFocal, false);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public Builder addKeyline(float offsetLoc, float mask, float maskedItemSize) {
            return addKeyline(offsetLoc, mask, maskedItemSize, false);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public Builder addKeyline(float offsetLoc, float mask, float maskedItemSize, boolean isFocal, boolean isAnchor, float cutoff) {
            if (maskedItemSize <= 0.0f) {
                return this;
            }
            if (isAnchor) {
                if (!isFocal) {
                    if (this.latestAnchorKeylineIndex != -1 && this.latestAnchorKeylineIndex != 0) {
                        throw new IllegalArgumentException("Anchor keylines must be either the first or last keyline.");
                    }
                    this.latestAnchorKeylineIndex = this.tmpKeylines.size();
                } else {
                    throw new IllegalArgumentException("Anchor keylines cannot be focal.");
                }
            }
            Keyline tmpKeyline = new Keyline(Float.MIN_VALUE, offsetLoc, mask, maskedItemSize, isAnchor, cutoff);
            if (isFocal) {
                if (this.tmpFirstFocalKeyline == null) {
                    this.tmpFirstFocalKeyline = tmpKeyline;
                    this.firstFocalKeylineIndex = this.tmpKeylines.size();
                }
                if (this.lastFocalKeylineIndex != -1 && this.tmpKeylines.size() - this.lastFocalKeylineIndex > 1) {
                    throw new IllegalArgumentException("Keylines marked as focal must be placed next to each other. There cannot be non-focal keylines between focal keylines.");
                }
                if (maskedItemSize != this.tmpFirstFocalKeyline.maskedItemSize) {
                    throw new IllegalArgumentException("Keylines that are marked as focal must all have the same masked item size.");
                }
                this.tmpLastFocalKeyline = tmpKeyline;
                this.lastFocalKeylineIndex = this.tmpKeylines.size();
            } else if (this.tmpFirstFocalKeyline == null && tmpKeyline.maskedItemSize < this.lastKeylineMaskedSize) {
                throw new IllegalArgumentException("Keylines before the first focal keyline must be ordered by incrementing masked item size.");
            } else {
                if (this.tmpLastFocalKeyline != null && tmpKeyline.maskedItemSize > this.lastKeylineMaskedSize) {
                    throw new IllegalArgumentException("Keylines after the last focal keyline must be ordered by decreasing masked item size.");
                }
            }
            this.lastKeylineMaskedSize = tmpKeyline.maskedItemSize;
            this.tmpKeylines.add(tmpKeyline);
            return this;
        }

        Builder addKeyline(float offsetLoc, float mask, float maskedItemSize, boolean isFocal, boolean isAnchor) {
            float cutoff = 0.0f;
            float keylineStart = offsetLoc - (maskedItemSize / 2.0f);
            float keylineEnd = (maskedItemSize / 2.0f) + offsetLoc;
            if (keylineEnd > this.availableSpace) {
                cutoff = Math.abs(keylineEnd - Math.max(keylineEnd - maskedItemSize, this.availableSpace));
            } else if (keylineStart < 0.0f) {
                cutoff = Math.abs(keylineStart - Math.min(keylineStart + maskedItemSize, 0.0f));
            }
            return addKeyline(offsetLoc, mask, maskedItemSize, isFocal, isAnchor, cutoff);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public Builder addAnchorKeyline(float offsetLoc, float mask, float maskedItemSize) {
            return addKeyline(offsetLoc, mask, maskedItemSize, false, true);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public Builder addKeylineRange(float offsetLoc, float mask, float maskedItemSize, int count) {
            return addKeylineRange(offsetLoc, mask, maskedItemSize, count, false);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public Builder addKeylineRange(float offsetLoc, float mask, float maskedItemSize, int count, boolean isFocal) {
            if (count <= 0 || maskedItemSize <= 0.0f) {
                return this;
            }
            for (int i = 0; i < count; i++) {
                float loc = (i * maskedItemSize) + offsetLoc;
                addKeyline(loc, mask, maskedItemSize, isFocal);
            }
            return this;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public KeylineState build() {
            if (this.tmpFirstFocalKeyline == null) {
                throw new IllegalStateException("There must be a keyline marked as focal.");
            }
            List<Keyline> keylines = new ArrayList<>();
            for (int i = 0; i < this.tmpKeylines.size(); i++) {
                Keyline tmpKeyline = this.tmpKeylines.get(i);
                Keyline keyline = new Keyline(calculateKeylineLocationForItemPosition(this.tmpFirstFocalKeyline.locOffset, this.itemSize, this.firstFocalKeylineIndex, i), tmpKeyline.locOffset, tmpKeyline.mask, tmpKeyline.maskedItemSize, tmpKeyline.isAnchor, tmpKeyline.cutoff);
                keylines.add(keyline);
            }
            return new KeylineState(this.itemSize, keylines, this.firstFocalKeylineIndex, this.lastFocalKeylineIndex);
        }

        private static float calculateKeylineLocationForItemPosition(float firstFocalLoc, float itemSize, int firstFocalPosition, int itemPosition) {
            return (firstFocalLoc - (firstFocalPosition * itemSize)) + (itemPosition * itemSize);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class Keyline {
        final float cutoff;
        final boolean isAnchor;
        final float loc;
        final float locOffset;
        final float mask;
        final float maskedItemSize;

        Keyline(float loc, float locOffset, float mask, float maskedItemSize) {
            this(loc, locOffset, mask, maskedItemSize, false, 0.0f);
        }

        Keyline(float loc, float locOffset, float mask, float maskedItemSize, boolean isAnchor, float cutoff) {
            this.loc = loc;
            this.locOffset = locOffset;
            this.mask = mask;
            this.maskedItemSize = maskedItemSize;
            this.isAnchor = isAnchor;
            this.cutoff = cutoff;
        }

        static Keyline lerp(Keyline from, Keyline to, float progress) {
            return new Keyline(AnimationUtils.lerp(from.loc, to.loc, progress), AnimationUtils.lerp(from.locOffset, to.locOffset, progress), AnimationUtils.lerp(from.mask, to.mask, progress), AnimationUtils.lerp(from.maskedItemSize, to.maskedItemSize, progress));
        }
    }
}
