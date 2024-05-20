package com.google.android.material.motion;

import android.os.Build;
import android.view.View;
import android.window.BackEvent;
import android.window.OnBackAnimationCallback;
import android.window.OnBackInvokedCallback;
import android.window.OnBackInvokedDispatcher;
import androidx.activity.BackEventCompat;
import java.util.Objects;
import kotlin.time.DurationKt;
/* loaded from: classes.dex */
public final class MaterialBackOrchestrator {
    private final BackCallbackDelegate backCallbackDelegate;
    private final MaterialBackHandler backHandler;
    private final View view;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public interface BackCallbackDelegate {
        void startListeningForBackCallbacks(MaterialBackHandler materialBackHandler, View view, boolean z);

        void stopListeningForBackCallbacks(View view);
    }

    public <T extends View & MaterialBackHandler> MaterialBackOrchestrator(T backHandlerView) {
        this(backHandlerView, backHandlerView);
    }

    public MaterialBackOrchestrator(MaterialBackHandler backHandler, View view) {
        this.backCallbackDelegate = createBackCallbackDelegate();
        this.backHandler = backHandler;
        this.view = view;
    }

    public boolean shouldListenForBackCallbacks() {
        return this.backCallbackDelegate != null;
    }

    public void startListeningForBackCallbacksWithPriorityOverlay() {
        startListeningForBackCallbacks(true);
    }

    public void startListeningForBackCallbacks() {
        startListeningForBackCallbacks(false);
    }

    private void startListeningForBackCallbacks(boolean priorityOverlay) {
        if (this.backCallbackDelegate != null) {
            this.backCallbackDelegate.startListeningForBackCallbacks(this.backHandler, this.view, priorityOverlay);
        }
    }

    public void stopListeningForBackCallbacks() {
        if (this.backCallbackDelegate != null) {
            this.backCallbackDelegate.stopListeningForBackCallbacks(this.view);
        }
    }

    private static BackCallbackDelegate createBackCallbackDelegate() {
        if (Build.VERSION.SDK_INT >= 34) {
            return new Api34BackCallbackDelegate();
        }
        if (Build.VERSION.SDK_INT >= 33) {
            return new Api33BackCallbackDelegate();
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class Api34BackCallbackDelegate extends Api33BackCallbackDelegate {
        private Api34BackCallbackDelegate() {
            super();
        }

        @Override // com.google.android.material.motion.MaterialBackOrchestrator.Api33BackCallbackDelegate
        OnBackInvokedCallback createOnBackInvokedCallback(final MaterialBackHandler backHandler) {
            return new OnBackAnimationCallback() { // from class: com.google.android.material.motion.MaterialBackOrchestrator.Api34BackCallbackDelegate.1
                public void onBackStarted(BackEvent backEvent) {
                    if (!Api34BackCallbackDelegate.this.isListeningForBackCallbacks()) {
                        return;
                    }
                    backHandler.startBackProgress(new BackEventCompat(backEvent));
                }

                public void onBackProgressed(BackEvent backEvent) {
                    if (!Api34BackCallbackDelegate.this.isListeningForBackCallbacks()) {
                        return;
                    }
                    backHandler.updateBackProgress(new BackEventCompat(backEvent));
                }

                public void onBackInvoked() {
                    backHandler.handleBackInvoked();
                }

                public void onBackCancelled() {
                    if (!Api34BackCallbackDelegate.this.isListeningForBackCallbacks()) {
                        return;
                    }
                    backHandler.cancelBackProgress();
                }
            };
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class Api33BackCallbackDelegate implements BackCallbackDelegate {
        private OnBackInvokedCallback onBackInvokedCallback;

        private Api33BackCallbackDelegate() {
        }

        boolean isListeningForBackCallbacks() {
            return this.onBackInvokedCallback != null;
        }

        @Override // com.google.android.material.motion.MaterialBackOrchestrator.BackCallbackDelegate
        public void startListeningForBackCallbacks(MaterialBackHandler backHandler, View view, boolean priorityOverlay) {
            OnBackInvokedDispatcher onBackInvokedDispatcher;
            int priority;
            if (this.onBackInvokedCallback != null || (onBackInvokedDispatcher = view.findOnBackInvokedDispatcher()) == null) {
                return;
            }
            this.onBackInvokedCallback = createOnBackInvokedCallback(backHandler);
            if (priorityOverlay) {
                priority = DurationKt.NANOS_IN_MILLIS;
            } else {
                priority = 0;
            }
            onBackInvokedDispatcher.registerOnBackInvokedCallback(priority, this.onBackInvokedCallback);
        }

        @Override // com.google.android.material.motion.MaterialBackOrchestrator.BackCallbackDelegate
        public void stopListeningForBackCallbacks(View view) {
            OnBackInvokedDispatcher onBackInvokedDispatcher = view.findOnBackInvokedDispatcher();
            if (onBackInvokedDispatcher == null) {
                return;
            }
            onBackInvokedDispatcher.unregisterOnBackInvokedCallback(this.onBackInvokedCallback);
            this.onBackInvokedCallback = null;
        }

        OnBackInvokedCallback createOnBackInvokedCallback(final MaterialBackHandler backHandler) {
            Objects.requireNonNull(backHandler);
            return new OnBackInvokedCallback() { // from class: com.google.android.material.motion.MaterialBackOrchestrator$Api33BackCallbackDelegate$$ExternalSyntheticLambda0
                public final void onBackInvoked() {
                    MaterialBackHandler.this.handleBackInvoked();
                }
            };
        }
    }
}
