package kotlin.sequences;

import androidx.constraintlayout.widget.ConstraintLayout;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.FunctionReferenceImpl;
import kotlin.jvm.internal.Intrinsics;
/* JADX INFO: Add missing generic type declarations: [R] */
/* compiled from: _Sequences.kt */
@Metadata(k = 3, mv = {1, 8, 0}, xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes.dex */
/* synthetic */ class SequencesKt___SequencesKt$flatMap$1<R> extends FunctionReferenceImpl implements Function1<Iterable<? extends R>, Iterator<? extends R>> {
    public static final SequencesKt___SequencesKt$flatMap$1 INSTANCE = new SequencesKt___SequencesKt$flatMap$1();

    SequencesKt___SequencesKt$flatMap$1() {
        super(1, Iterable.class, "iterator", "iterator()Ljava/util/Iterator;", 0);
    }

    @Override // kotlin.jvm.functions.Function1
    public /* bridge */ /* synthetic */ Object invoke(Object p1) {
        return invoke((Iterable) ((Iterable) p1));
    }

    public final Iterator<R> invoke(Iterable<? extends R> p0) {
        Intrinsics.checkNotNullParameter(p0, "p0");
        return (Iterator<? extends R>) p0.iterator();
    }
}