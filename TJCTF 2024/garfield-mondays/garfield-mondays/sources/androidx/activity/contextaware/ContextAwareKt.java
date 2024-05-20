package androidx.activity.contextaware;

import android.content.Context;
import androidx.constraintlayout.widget.ConstraintLayout;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugProbesKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.InlineMarker;
import kotlinx.coroutines.CancellableContinuationImpl;
/* compiled from: ContextAware.kt */
@Metadata(d1 = {"\u0000\u001a\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\u001a@\u0010\u0000\u001a\u0007H\u0001¢\u0006\u0002\b\u0002\"\u0004\b\u0000\u0010\u0001*\u00020\u00032\u001e\b\u0004\u0010\u0004\u001a\u0018\u0012\t\u0012\u00070\u0006¢\u0006\u0002\b\u0002\u0012\t\u0012\u0007H\u0001¢\u0006\u0002\b\u00020\u0005H\u0086Hø\u0001\u0000¢\u0006\u0002\u0010\u0007\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006\b"}, d2 = {"withContextAvailable", "R", "Lkotlin/jvm/JvmSuppressWildcards;", "Landroidx/activity/contextaware/ContextAware;", "onContextAvailable", "Lkotlin/Function1;", "Landroid/content/Context;", "(Landroidx/activity/contextaware/ContextAware;Lkotlin/jvm/functions/Function1;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "activity_release"}, k = 2, mv = {1, 8, 0}, xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes.dex */
public final class ContextAwareKt {
    public static final <R> Object withContextAvailable(ContextAware $this$withContextAvailable, Function1<Context, R> function1, Continuation<R> continuation) {
        Context availableContext = $this$withContextAvailable.peekAvailableContext();
        if (availableContext != null) {
            return function1.invoke(availableContext);
        }
        CancellableContinuationImpl cancellable$iv = new CancellableContinuationImpl(IntrinsicsKt.intercepted(continuation), 1);
        cancellable$iv.initCancellability();
        CancellableContinuationImpl co = cancellable$iv;
        ContextAwareKt$withContextAvailable$2$listener$1 listener = new ContextAwareKt$withContextAvailable$2$listener$1(co, function1);
        $this$withContextAvailable.addOnContextAvailableListener(listener);
        co.invokeOnCancellation(new ContextAwareKt$withContextAvailable$2$1($this$withContextAvailable, listener));
        Object result = cancellable$iv.getResult();
        if (result == IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
            DebugProbesKt.probeCoroutineSuspended(continuation);
        }
        return result;
    }

    private static final <R> Object withContextAvailable$$forInline(ContextAware $this$withContextAvailable, Function1<Context, R> function1, Continuation<R> continuation) {
        Context availableContext = $this$withContextAvailable.peekAvailableContext();
        if (availableContext != null) {
            return function1.invoke(availableContext);
        }
        InlineMarker.mark(0);
        CancellableContinuationImpl cancellable$iv = new CancellableContinuationImpl(IntrinsicsKt.intercepted(continuation), 1);
        cancellable$iv.initCancellability();
        CancellableContinuationImpl co = cancellable$iv;
        ContextAwareKt$withContextAvailable$2$listener$1 listener = new ContextAwareKt$withContextAvailable$2$listener$1(co, function1);
        $this$withContextAvailable.addOnContextAvailableListener(listener);
        co.invokeOnCancellation(new ContextAwareKt$withContextAvailable$2$1($this$withContextAvailable, listener));
        Unit unit = Unit.INSTANCE;
        Object result = cancellable$iv.getResult();
        if (result == IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
            DebugProbesKt.probeCoroutineSuspended(continuation);
        }
        InlineMarker.mark(1);
        return result;
    }
}
