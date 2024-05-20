package kotlinx.coroutines;

import androidx.constraintlayout.widget.ConstraintLayout;
import kotlin.Metadata;
import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.jvm.functions.Function2;
/* compiled from: Builders.kt */
@Metadata(d1 = {"\u0000\"\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\u001aT\u0010\u0000\u001a\u0002H\u0001\"\u0004\b\u0000\u0010\u00012\b\b\u0002\u0010\u0002\u001a\u00020\u00032'\u0010\u0004\u001a#\b\u0001\u0012\u0004\u0012\u00020\u0006\u0012\n\u0012\b\u0012\u0004\u0012\u0002H\u00010\u0007\u0012\u0006\u0012\u0004\u0018\u00010\b0\u0005¢\u0006\u0002\b\tø\u0001\u0000\u0082\u0002\n\n\b\b\u0001\u0012\u0002\u0010\u0002 \u0001¢\u0006\u0002\u0010\n\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006\u000b"}, d2 = {"runBlocking", "T", "context", "Lkotlin/coroutines/CoroutineContext;", "block", "Lkotlin/Function2;", "Lkotlinx/coroutines/CoroutineScope;", "Lkotlin/coroutines/Continuation;", "", "Lkotlin/ExtensionFunctionType;", "(Lkotlin/coroutines/CoroutineContext;Lkotlin/jvm/functions/Function2;)Ljava/lang/Object;", "kotlinx-coroutines-core"}, k = 5, mv = {1, 6, 0}, xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE, xs = "kotlinx/coroutines/BuildersKt")
/* loaded from: classes.dex */
public final /* synthetic */ class BuildersKt__BuildersKt {
    public static /* synthetic */ Object runBlocking$default(CoroutineContext coroutineContext, Function2 function2, int i, Object obj) throws InterruptedException {
        if ((i & 1) != 0) {
            coroutineContext = EmptyCoroutineContext.INSTANCE;
        }
        return BuildersKt.runBlocking(coroutineContext, function2);
    }

    /* JADX WARN: Code restructure failed: missing block: B:31:0x003e, code lost:
        if (r5 == null) goto L16;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final <T> T runBlocking(kotlin.coroutines.CoroutineContext r8, kotlin.jvm.functions.Function2<? super kotlinx.coroutines.CoroutineScope, ? super kotlin.coroutines.Continuation<? super T>, ? extends java.lang.Object> r9) throws java.lang.InterruptedException {
        /*
            java.lang.Thread r0 = java.lang.Thread.currentThread()
            kotlin.coroutines.ContinuationInterceptor$Key r1 = kotlin.coroutines.ContinuationInterceptor.Key
            kotlin.coroutines.CoroutineContext$Key r1 = (kotlin.coroutines.CoroutineContext.Key) r1
            kotlin.coroutines.CoroutineContext$Element r1 = r8.get(r1)
            kotlin.coroutines.ContinuationInterceptor r1 = (kotlin.coroutines.ContinuationInterceptor) r1
            r2 = 0
            r3 = 0
            if (r1 != 0) goto L29
            kotlinx.coroutines.ThreadLocalEventLoop r4 = kotlinx.coroutines.ThreadLocalEventLoop.INSTANCE
            kotlinx.coroutines.EventLoop r2 = r4.getEventLoop$kotlinx_coroutines_core()
            kotlinx.coroutines.GlobalScope r4 = kotlinx.coroutines.GlobalScope.INSTANCE
            kotlinx.coroutines.CoroutineScope r4 = (kotlinx.coroutines.CoroutineScope) r4
            r5 = r2
            kotlin.coroutines.CoroutineContext r5 = (kotlin.coroutines.CoroutineContext) r5
            kotlin.coroutines.CoroutineContext r5 = r8.plus(r5)
            kotlin.coroutines.CoroutineContext r3 = kotlinx.coroutines.CoroutineContextKt.newCoroutineContext(r4, r5)
            goto L4f
        L29:
            boolean r4 = r1 instanceof kotlinx.coroutines.EventLoop
            r5 = 0
            if (r4 == 0) goto L32
            r4 = r1
            kotlinx.coroutines.EventLoop r4 = (kotlinx.coroutines.EventLoop) r4
            goto L33
        L32:
            r4 = r5
        L33:
            if (r4 == 0) goto L40
            r6 = r4
            r7 = 0
            boolean r6 = r6.shouldBeProcessedFromContext()
            if (r6 == 0) goto L3e
            r5 = r4
        L3e:
            if (r5 != 0) goto L46
        L40:
            kotlinx.coroutines.ThreadLocalEventLoop r4 = kotlinx.coroutines.ThreadLocalEventLoop.INSTANCE
            kotlinx.coroutines.EventLoop r5 = r4.currentOrNull$kotlinx_coroutines_core()
        L46:
            r2 = r5
            kotlinx.coroutines.GlobalScope r4 = kotlinx.coroutines.GlobalScope.INSTANCE
            kotlinx.coroutines.CoroutineScope r4 = (kotlinx.coroutines.CoroutineScope) r4
            kotlin.coroutines.CoroutineContext r3 = kotlinx.coroutines.CoroutineContextKt.newCoroutineContext(r4, r8)
        L4f:
            kotlinx.coroutines.BlockingCoroutine r4 = new kotlinx.coroutines.BlockingCoroutine
            r4.<init>(r3, r0, r2)
            kotlinx.coroutines.CoroutineStart r5 = kotlinx.coroutines.CoroutineStart.DEFAULT
            r4.start(r5, r4, r9)
            java.lang.Object r5 = r4.joinBlocking()
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.BuildersKt__BuildersKt.runBlocking(kotlin.coroutines.CoroutineContext, kotlin.jvm.functions.Function2):java.lang.Object");
    }
}
