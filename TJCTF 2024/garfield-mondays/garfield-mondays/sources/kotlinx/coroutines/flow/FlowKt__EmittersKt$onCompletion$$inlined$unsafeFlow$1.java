package kotlinx.coroutines.flow;

import androidx.constraintlayout.widget.ConstraintLayout;
import kotlin.Metadata;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.jvm.functions.Function3;
/* JADX INFO: Add missing generic type declarations: [T] */
/* compiled from: SafeCollector.common.kt */
@Metadata(d1 = {"\u0000\u0019\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002*\u0001\u0000\b\n\u0018\u00002\b\u0012\u0004\u0012\u00028\u00000\u0001J\u001f\u0010\u0002\u001a\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u00028\u00000\u0005H\u0096@ø\u0001\u0000¢\u0006\u0002\u0010\u0006\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006\u0007¸\u0006\u0000"}, d2 = {"kotlinx/coroutines/flow/internal/SafeCollector_commonKt$unsafeFlow$1", "Lkotlinx/coroutines/flow/Flow;", "collect", "", "collector", "Lkotlinx/coroutines/flow/FlowCollector;", "(Lkotlinx/coroutines/flow/FlowCollector;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "kotlinx-coroutines-core"}, k = 1, mv = {1, 6, 0}, xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes.dex */
public final class FlowKt__EmittersKt$onCompletion$$inlined$unsafeFlow$1<T> implements Flow<T> {
    final /* synthetic */ Function3 $action$inlined;
    final /* synthetic */ Flow $this_onCompletion$inlined;

    /* compiled from: SafeCollector.common.kt */
    @Metadata(k = 3, mv = {1, 6, 0}, xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
    @DebugMetadata(c = "kotlinx.coroutines.flow.FlowKt__EmittersKt$onCompletion$$inlined$unsafeFlow$1", f = "Emitters.kt", i = {0, 0, 1, 2}, l = {114, 121, 128}, m = "collect", n = {"this", "$this$onCompletion_u24lambda_u2d2", "e", "sc"}, s = {"L$0", "L$1", "L$0", "L$0"})
    /* renamed from: kotlinx.coroutines.flow.FlowKt__EmittersKt$onCompletion$$inlined$unsafeFlow$1$1  reason: invalid class name */
    /* loaded from: classes.dex */
    public static final class AnonymousClass1 extends ContinuationImpl {
        Object L$0;
        Object L$1;
        int label;
        /* synthetic */ Object result;

        public AnonymousClass1(Continuation continuation) {
            super(continuation);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        public final Object invokeSuspend(Object obj) {
            this.result = obj;
            this.label |= Integer.MIN_VALUE;
            return FlowKt__EmittersKt$onCompletion$$inlined$unsafeFlow$1.this.collect(null, this);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0026  */
    /* JADX WARN: Removed duplicated region for block: B:12:0x002e  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0039  */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0043  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0050  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x008e A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:29:0x008f  */
    @Override // kotlinx.coroutines.flow.Flow
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object collect(kotlinx.coroutines.flow.FlowCollector<? super T> r10, kotlin.coroutines.Continuation<? super kotlin.Unit> r11) {
        /*
            r9 = this;
            boolean r0 = r11 instanceof kotlinx.coroutines.flow.FlowKt__EmittersKt$onCompletion$$inlined$unsafeFlow$1.AnonymousClass1
            if (r0 == 0) goto L14
            r0 = r11
            kotlinx.coroutines.flow.FlowKt__EmittersKt$onCompletion$$inlined$unsafeFlow$1$1 r0 = (kotlinx.coroutines.flow.FlowKt__EmittersKt$onCompletion$$inlined$unsafeFlow$1.AnonymousClass1) r0
            int r1 = r0.label
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r1 = r1 & r2
            if (r1 == 0) goto L14
            int r11 = r0.label
            int r11 = r11 - r2
            r0.label = r11
            goto L19
        L14:
            kotlinx.coroutines.flow.FlowKt__EmittersKt$onCompletion$$inlined$unsafeFlow$1$1 r0 = new kotlinx.coroutines.flow.FlowKt__EmittersKt$onCompletion$$inlined$unsafeFlow$1$1
            r0.<init>(r11)
        L19:
            r11 = r0
            java.lang.Object r0 = r11.result
            java.lang.Object r1 = kotlin.coroutines.intrinsics.IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r2 = r11.label
            r3 = 0
            switch(r2) {
                case 0: goto L50;
                case 1: goto L43;
                case 2: goto L39;
                case 3: goto L2e;
                default: goto L26;
            }
        L26:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L2e:
            r10 = 0
            java.lang.Object r1 = r11.L$0
            kotlinx.coroutines.flow.internal.SafeCollector r1 = (kotlinx.coroutines.flow.internal.SafeCollector) r1
            kotlin.ResultKt.throwOnFailure(r0)     // Catch: java.lang.Throwable -> L37
            goto L90
        L37:
            r2 = move-exception
            goto L9c
        L39:
            r10 = 0
            java.lang.Object r1 = r11.L$0
            java.lang.Throwable r1 = (java.lang.Throwable) r1
            kotlin.ResultKt.throwOnFailure(r0)
            goto Lb9
        L43:
            r10 = 0
            java.lang.Object r2 = r11.L$1
            kotlinx.coroutines.flow.FlowCollector r2 = (kotlinx.coroutines.flow.FlowCollector) r2
            java.lang.Object r4 = r11.L$0
            kotlinx.coroutines.flow.FlowKt__EmittersKt$onCompletion$$inlined$unsafeFlow$1 r4 = (kotlinx.coroutines.flow.FlowKt__EmittersKt$onCompletion$$inlined$unsafeFlow$1) r4
            kotlin.ResultKt.throwOnFailure(r0)     // Catch: java.lang.Throwable -> La0
            goto L6a
        L50:
            kotlin.ResultKt.throwOnFailure(r0)
            r4 = r9
            r2 = r11
            kotlin.coroutines.Continuation r2 = (kotlin.coroutines.Continuation) r2
            r2 = r10
            r10 = 0
            kotlinx.coroutines.flow.Flow r5 = r4.$this_onCompletion$inlined     // Catch: java.lang.Throwable -> La0
            r11.L$0 = r4     // Catch: java.lang.Throwable -> La0
            r11.L$1 = r2     // Catch: java.lang.Throwable -> La0
            r6 = 1
            r11.label = r6     // Catch: java.lang.Throwable -> La0
            java.lang.Object r5 = r5.collect(r2, r11)     // Catch: java.lang.Throwable -> La0
            if (r5 != r1) goto L6a
            return r1
        L6a:
            kotlinx.coroutines.flow.internal.SafeCollector r5 = new kotlinx.coroutines.flow.internal.SafeCollector
            r6 = 0
            kotlin.coroutines.CoroutineContext r7 = r11.getContext()
            r5.<init>(r2, r7)
            r2 = r5
            kotlin.jvm.functions.Function3 r5 = r4.$action$inlined     // Catch: java.lang.Throwable -> L98
            r11.L$0 = r2     // Catch: java.lang.Throwable -> L98
            r11.L$1 = r3     // Catch: java.lang.Throwable -> L98
            r6 = 3
            r11.label = r6     // Catch: java.lang.Throwable -> L98
            r6 = 6
            kotlin.jvm.internal.InlineMarker.mark(r6)     // Catch: java.lang.Throwable -> L98
            java.lang.Object r3 = r5.invoke(r2, r3, r11)     // Catch: java.lang.Throwable -> L98
            r5 = 7
            kotlin.jvm.internal.InlineMarker.mark(r5)     // Catch: java.lang.Throwable -> L98
            if (r3 != r1) goto L8f
            return r1
        L8f:
            r1 = r2
        L90:
            r1.releaseIntercepted()
            kotlin.Unit r10 = kotlin.Unit.INSTANCE
            return r10
        L98:
            r1 = move-exception
            r8 = r2
            r2 = r1
            r1 = r8
        L9c:
            r1.releaseIntercepted()
            throw r2
        La0:
            r2 = move-exception
            kotlinx.coroutines.flow.ThrowingCollector r5 = new kotlinx.coroutines.flow.ThrowingCollector
            r5.<init>(r2)
            kotlinx.coroutines.flow.FlowCollector r5 = (kotlinx.coroutines.flow.FlowCollector) r5
            kotlin.jvm.functions.Function3 r6 = r4.$action$inlined
            r11.L$0 = r2
            r11.L$1 = r3
            r3 = 2
            r11.label = r3
            java.lang.Object r3 = kotlinx.coroutines.flow.FlowKt__EmittersKt.access$invokeSafely$FlowKt__EmittersKt(r5, r6, r2, r11)
            if (r3 != r1) goto Lb8
            return r1
        Lb8:
            r1 = r2
        Lb9:
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.FlowKt__EmittersKt$onCompletion$$inlined$unsafeFlow$1.collect(kotlinx.coroutines.flow.FlowCollector, kotlin.coroutines.Continuation):java.lang.Object");
    }

    public FlowKt__EmittersKt$onCompletion$$inlined$unsafeFlow$1(Flow flow, Function3 function3) {
        this.$this_onCompletion$inlined = flow;
        this.$action$inlined = function3;
    }
}
