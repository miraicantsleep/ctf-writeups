package androidx.lifecycle;

import androidx.constraintlayout.widget.ConstraintLayout;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.Dispatchers;
import kotlinx.coroutines.Job;
import kotlinx.coroutines.SupervisorKt;
/* compiled from: Lifecycle.kt */
@Metadata(d1 = {"\u0000\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\"\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00028F¢\u0006\u0006\u001a\u0004\b\u0003\u0010\u0004¨\u0006\u0005"}, d2 = {"coroutineScope", "Landroidx/lifecycle/LifecycleCoroutineScope;", "Landroidx/lifecycle/Lifecycle;", "getCoroutineScope", "(Landroidx/lifecycle/Lifecycle;)Landroidx/lifecycle/LifecycleCoroutineScope;", "lifecycle-common"}, k = 2, mv = {1, 8, 0}, xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes.dex */
public final class LifecycleKt {
    public static final LifecycleCoroutineScope getCoroutineScope(Lifecycle $this$coroutineScope) {
        LifecycleCoroutineScopeImpl newScope;
        Intrinsics.checkNotNullParameter($this$coroutineScope, "<this>");
        do {
            LifecycleCoroutineScopeImpl existing = (LifecycleCoroutineScopeImpl) $this$coroutineScope.getInternalScopeRef().get();
            if (existing != null) {
                return existing;
            }
            newScope = new LifecycleCoroutineScopeImpl($this$coroutineScope, SupervisorKt.SupervisorJob$default((Job) null, 1, (Object) null).plus(Dispatchers.getMain().getImmediate()));
        } while (!LifecycleKt$$ExternalSyntheticBackportWithForwarding0.m($this$coroutineScope.getInternalScopeRef(), null, newScope));
        newScope.register();
        return newScope;
    }
}
