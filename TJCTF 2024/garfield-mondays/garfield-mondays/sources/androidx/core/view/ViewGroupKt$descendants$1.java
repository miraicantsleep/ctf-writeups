package androidx.core.view;

import android.view.View;
import android.view.ViewGroup;
import androidx.constraintlayout.widget.ConstraintLayout;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.RestrictedSuspendLambda;
import kotlin.jvm.functions.Function2;
import kotlin.sequences.SequenceScope;
/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: ViewGroup.kt */
@Metadata(d1 = {"\u0000\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\u0010\u0000\u001a\u00020\u0001*\b\u0012\u0004\u0012\u00020\u00030\u0002H\u008a@"}, d2 = {"<anonymous>", "", "Lkotlin/sequences/SequenceScope;", "Landroid/view/View;"}, k = 3, mv = {1, 7, 1}, xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
@DebugMetadata(c = "androidx.core.view.ViewGroupKt$descendants$1", f = "ViewGroup.kt", i = {0, 0, 0, 0, 1, 1, 1}, l = {119, 121}, m = "invokeSuspend", n = {"$this$sequence", "$this$forEach$iv", "child", "index$iv", "$this$sequence", "$this$forEach$iv", "index$iv"}, s = {"L$0", "L$1", "L$2", "I$0", "L$0", "L$1", "I$0"})
/* loaded from: classes.dex */
public final class ViewGroupKt$descendants$1 extends RestrictedSuspendLambda implements Function2<SequenceScope<? super View>, Continuation<? super Unit>, Object> {
    final /* synthetic */ ViewGroup $this_descendants;
    int I$0;
    int I$1;
    private /* synthetic */ Object L$0;
    Object L$1;
    Object L$2;
    int label;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ViewGroupKt$descendants$1(ViewGroup viewGroup, Continuation<? super ViewGroupKt$descendants$1> continuation) {
        super(2, continuation);
        this.$this_descendants = viewGroup;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public final Continuation<Unit> create(Object obj, Continuation<?> continuation) {
        ViewGroupKt$descendants$1 viewGroupKt$descendants$1 = new ViewGroupKt$descendants$1(this.$this_descendants, continuation);
        viewGroupKt$descendants$1.L$0 = obj;
        return viewGroupKt$descendants$1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(SequenceScope<? super View> sequenceScope, Continuation<? super Unit> continuation) {
        return ((ViewGroupKt$descendants$1) create(sequenceScope, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x004f  */
    /* JADX WARN: Removed duplicated region for block: B:16:0x0077  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x009a  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x00a0  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:19:0x0093 -> B:20:0x0095). Please submit an issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:21:0x009a -> B:22:0x009e). Please submit an issue!!! */
    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r14) {
        /*
            r13 = this;
            java.lang.Object r0 = kotlin.coroutines.intrinsics.IntrinsicsKt.getCOROUTINE_SUSPENDED()
            int r1 = r13.label
            r2 = 1
            switch(r1) {
                case 0: goto L3d;
                case 1: goto L26;
                case 2: goto L12;
                default: goto La;
            }
        La:
            java.lang.IllegalStateException r14 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r14.<init>(r0)
            throw r14
        L12:
            r1 = r13
            r3 = 0
            r4 = 0
            int r5 = r1.I$1
            int r6 = r1.I$0
            java.lang.Object r7 = r1.L$1
            android.view.ViewGroup r7 = (android.view.ViewGroup) r7
            java.lang.Object r8 = r1.L$0
            kotlin.sequences.SequenceScope r8 = (kotlin.sequences.SequenceScope) r8
            kotlin.ResultKt.throwOnFailure(r14)
            goto L95
        L26:
            r1 = r13
            r3 = 0
            r4 = 0
            int r5 = r1.I$1
            int r6 = r1.I$0
            java.lang.Object r7 = r1.L$2
            android.view.View r7 = (android.view.View) r7
            java.lang.Object r8 = r1.L$1
            android.view.ViewGroup r8 = (android.view.ViewGroup) r8
            java.lang.Object r9 = r1.L$0
            kotlin.sequences.SequenceScope r9 = (kotlin.sequences.SequenceScope) r9
            kotlin.ResultKt.throwOnFailure(r14)
            goto L73
        L3d:
            kotlin.ResultKt.throwOnFailure(r14)
            r1 = r13
            java.lang.Object r3 = r1.L$0
            kotlin.sequences.SequenceScope r3 = (kotlin.sequences.SequenceScope) r3
            android.view.ViewGroup r4 = r1.$this_descendants
            r5 = 0
            r6 = 0
            int r7 = r4.getChildCount()
        L4d:
            if (r6 >= r7) goto La0
            android.view.View r8 = r4.getChildAt(r6)
            java.lang.String r9 = "getChildAt(index)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r9)
            r9 = 0
            r1.L$0 = r3
            r1.L$1 = r4
            r1.L$2 = r8
            r1.I$0 = r6
            r1.I$1 = r7
            r1.label = r2
            java.lang.Object r10 = r3.yield(r8, r1)
            if (r10 != r0) goto L6c
            return r0
        L6c:
            r12 = r9
            r9 = r3
            r3 = r5
            r5 = r7
            r7 = r8
            r8 = r4
            r4 = r12
        L73:
            boolean r10 = r7 instanceof android.view.ViewGroup
            if (r10 == 0) goto L9a
            r10 = r7
            android.view.ViewGroup r10 = (android.view.ViewGroup) r10
            kotlin.sequences.Sequence r10 = androidx.core.view.ViewGroupKt.getDescendants(r10)
            r1.L$0 = r9
            r1.L$1 = r8
            r11 = 0
            r1.L$2 = r11
            r1.I$0 = r6
            r1.I$1 = r5
            r11 = 2
            r1.label = r11
            java.lang.Object r7 = r9.yieldAll(r10, r1)
            if (r7 != r0) goto L93
            return r0
        L93:
            r7 = r8
            r8 = r9
        L95:
            r4 = r7
            r7 = r5
            r5 = r3
            r3 = r8
            goto L9e
        L9a:
            r7 = r5
            r4 = r8
            r5 = r3
            r3 = r9
        L9e:
            int r6 = r6 + r2
            goto L4d
        La0:
            kotlin.Unit r0 = kotlin.Unit.INSTANCE
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.view.ViewGroupKt$descendants$1.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
