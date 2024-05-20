package androidx.lifecycle;

import android.os.Binder;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.Size;
import android.util.SizeF;
import android.util.SparseArray;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.os.BundleKt;
import androidx.savedstate.SavedStateRegistry;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import kotlin.Metadata;
import kotlin.TuplesKt;
import kotlin.collections.MapsKt;
import kotlin.collections.SetsKt;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.FlowKt;
import kotlinx.coroutines.flow.MutableStateFlow;
import kotlinx.coroutines.flow.StateFlow;
import kotlinx.coroutines.flow.StateFlowKt;
/* compiled from: SavedStateHandle.kt */
@Metadata(d1 = {"\u0000X\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010$\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010%\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\"\n\u0002\b\t\u0018\u0000 *2\u00020\u0001:\u0002*+B\u001d\b\u0016\u0012\u0014\u0010\u0002\u001a\u0010\u0012\u0004\u0012\u00020\u0004\u0012\u0006\u0012\u0004\u0018\u00010\u00010\u0003¢\u0006\u0002\u0010\u0005B\u0007\b\u0016¢\u0006\u0002\u0010\u0006J\u0010\u0010\u0010\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u0004H\u0007J\u0011\u0010\u0013\u001a\u00020\u00142\u0006\u0010\u0012\u001a\u00020\u0004H\u0087\u0002J\u001e\u0010\u0015\u001a\u0004\u0018\u0001H\u0016\"\u0004\b\u0000\u0010\u00162\u0006\u0010\u0012\u001a\u00020\u0004H\u0087\u0002¢\u0006\u0002\u0010\u0017J\u001c\u0010\u0018\u001a\b\u0012\u0004\u0012\u0002H\u00160\u0019\"\u0004\b\u0000\u0010\u00162\u0006\u0010\u0012\u001a\u00020\u0004H\u0007J)\u0010\u0018\u001a\b\u0012\u0004\u0012\u0002H\u00160\u0019\"\u0004\b\u0000\u0010\u00162\u0006\u0010\u0012\u001a\u00020\u00042\u0006\u0010\u001a\u001a\u0002H\u0016H\u0007¢\u0006\u0002\u0010\u001bJ1\u0010\u001c\u001a\b\u0012\u0004\u0012\u0002H\u00160\u0019\"\u0004\b\u0000\u0010\u00162\u0006\u0010\u0012\u001a\u00020\u00042\u0006\u0010\u001d\u001a\u00020\u00142\u0006\u0010\u001a\u001a\u0002H\u0016H\u0002¢\u0006\u0002\u0010\u001eJ)\u0010\u001f\u001a\b\u0012\u0004\u0012\u0002H\u00160 \"\u0004\b\u0000\u0010\u00162\u0006\u0010\u0012\u001a\u00020\u00042\u0006\u0010\u001a\u001a\u0002H\u0016H\u0007¢\u0006\u0002\u0010!J\u000e\u0010\"\u001a\b\u0012\u0004\u0012\u00020\u00040#H\u0007J\u001d\u0010$\u001a\u0004\u0018\u0001H\u0016\"\u0004\b\u0000\u0010\u00162\u0006\u0010\u0012\u001a\u00020\u0004H\u0007¢\u0006\u0002\u0010\u0017J\b\u0010\r\u001a\u00020\u000eH\u0007J&\u0010%\u001a\u00020\u0011\"\u0004\b\u0000\u0010\u00162\u0006\u0010\u0012\u001a\u00020\u00042\b\u0010&\u001a\u0004\u0018\u0001H\u0016H\u0087\u0002¢\u0006\u0002\u0010'J\u0018\u0010(\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u00042\u0006\u0010)\u001a\u00020\u000eH\u0007R\"\u0010\u0007\u001a\u0016\u0012\u0004\u0012\u00020\u0004\u0012\f\u0012\n\u0012\u0006\u0012\u0004\u0018\u00010\u00010\t0\bX\u0082\u0004¢\u0006\u0002\n\u0000R\u001e\u0010\n\u001a\u0012\u0012\u0004\u0012\u00020\u0004\u0012\b\u0012\u0006\u0012\u0002\b\u00030\u000b0\bX\u0082\u0004¢\u0006\u0002\n\u0000R\u001c\u0010\f\u001a\u0010\u0012\u0004\u0012\u00020\u0004\u0012\u0006\u0012\u0004\u0018\u00010\u00010\bX\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\r\u001a\u00020\u000eX\u0082\u0004¢\u0006\u0002\n\u0000R\u001a\u0010\u000f\u001a\u000e\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020\u000e0\bX\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006,"}, d2 = {"Landroidx/lifecycle/SavedStateHandle;", "", "initialState", "", "", "(Ljava/util/Map;)V", "()V", "flows", "", "Lkotlinx/coroutines/flow/MutableStateFlow;", "liveDatas", "Landroidx/lifecycle/SavedStateHandle$SavingStateLiveData;", "regular", "savedStateProvider", "Landroidx/savedstate/SavedStateRegistry$SavedStateProvider;", "savedStateProviders", "clearSavedStateProvider", "", "key", "contains", "", "get", "T", "(Ljava/lang/String;)Ljava/lang/Object;", "getLiveData", "Landroidx/lifecycle/MutableLiveData;", "initialValue", "(Ljava/lang/String;Ljava/lang/Object;)Landroidx/lifecycle/MutableLiveData;", "getLiveDataInternal", "hasInitialValue", "(Ljava/lang/String;ZLjava/lang/Object;)Landroidx/lifecycle/MutableLiveData;", "getStateFlow", "Lkotlinx/coroutines/flow/StateFlow;", "(Ljava/lang/String;Ljava/lang/Object;)Lkotlinx/coroutines/flow/StateFlow;", SavedStateHandle.KEYS, "", "remove", "set", "value", "(Ljava/lang/String;Ljava/lang/Object;)V", "setSavedStateProvider", "provider", "Companion", "SavingStateLiveData", "lifecycle-viewmodel-savedstate_release"}, k = 1, mv = {1, 8, 0}, xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes.dex */
public final class SavedStateHandle {
    private static final String KEYS = "keys";
    private static final String VALUES = "values";
    private final Map<String, MutableStateFlow<Object>> flows;
    private final Map<String, SavingStateLiveData<?>> liveDatas;
    private final Map<String, Object> regular;
    private final SavedStateRegistry.SavedStateProvider savedStateProvider;
    private final Map<String, SavedStateRegistry.SavedStateProvider> savedStateProviders;
    public static final Companion Companion = new Companion(null);
    private static final Class<? extends Object>[] ACCEPTABLE_CLASSES = {Boolean.TYPE, boolean[].class, Double.TYPE, double[].class, Integer.TYPE, int[].class, Long.TYPE, long[].class, String.class, String[].class, Binder.class, Bundle.class, Byte.TYPE, byte[].class, Character.TYPE, char[].class, CharSequence.class, CharSequence[].class, ArrayList.class, Float.TYPE, float[].class, Parcelable.class, Parcelable[].class, Serializable.class, Short.TYPE, short[].class, SparseArray.class, Size.class, SizeF.class};

    @JvmStatic
    public static final SavedStateHandle createHandle(Bundle bundle, Bundle bundle2) {
        return Companion.createHandle(bundle, bundle2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Bundle savedStateProvider$lambda$0(SavedStateHandle this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Map map = MapsKt.toMap(this$0.savedStateProviders);
        for (Map.Entry entry : map.entrySet()) {
            Bundle savedState = ((SavedStateRegistry.SavedStateProvider) entry.getValue()).saveState();
            this$0.set((String) entry.getKey(), savedState);
        }
        Set keySet = this$0.regular.keySet();
        ArrayList keys = new ArrayList(keySet.size());
        ArrayList value = new ArrayList(keys.size());
        for (String key : keySet) {
            keys.add(key);
            value.add(this$0.regular.get(key));
        }
        return BundleKt.bundleOf(TuplesKt.to(KEYS, keys), TuplesKt.to(VALUES, value));
    }

    public SavedStateHandle(Map<String, ? extends Object> initialState) {
        Intrinsics.checkNotNullParameter(initialState, "initialState");
        this.regular = new LinkedHashMap();
        this.savedStateProviders = new LinkedHashMap();
        this.liveDatas = new LinkedHashMap();
        this.flows = new LinkedHashMap();
        this.savedStateProvider = new SavedStateRegistry.SavedStateProvider() { // from class: androidx.lifecycle.SavedStateHandle$$ExternalSyntheticLambda0
            @Override // androidx.savedstate.SavedStateRegistry.SavedStateProvider
            public final Bundle saveState() {
                Bundle savedStateProvider$lambda$0;
                savedStateProvider$lambda$0 = SavedStateHandle.savedStateProvider$lambda$0(SavedStateHandle.this);
                return savedStateProvider$lambda$0;
            }
        };
        this.regular.putAll(initialState);
    }

    public SavedStateHandle() {
        this.regular = new LinkedHashMap();
        this.savedStateProviders = new LinkedHashMap();
        this.liveDatas = new LinkedHashMap();
        this.flows = new LinkedHashMap();
        this.savedStateProvider = new SavedStateRegistry.SavedStateProvider() { // from class: androidx.lifecycle.SavedStateHandle$$ExternalSyntheticLambda0
            @Override // androidx.savedstate.SavedStateRegistry.SavedStateProvider
            public final Bundle saveState() {
                Bundle savedStateProvider$lambda$0;
                savedStateProvider$lambda$0 = SavedStateHandle.savedStateProvider$lambda$0(SavedStateHandle.this);
                return savedStateProvider$lambda$0;
            }
        };
    }

    public final SavedStateRegistry.SavedStateProvider savedStateProvider() {
        return this.savedStateProvider;
    }

    public final boolean contains(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        return this.regular.containsKey(key);
    }

    public final <T> MutableLiveData<T> getLiveData(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        MutableLiveData<T> liveDataInternal = getLiveDataInternal(key, false, null);
        Intrinsics.checkNotNull(liveDataInternal, "null cannot be cast to non-null type androidx.lifecycle.MutableLiveData<T of androidx.lifecycle.SavedStateHandle.getLiveData>");
        return liveDataInternal;
    }

    public final <T> MutableLiveData<T> getLiveData(String key, T t) {
        Intrinsics.checkNotNullParameter(key, "key");
        return getLiveDataInternal(key, true, t);
    }

    private final <T> MutableLiveData<T> getLiveDataInternal(String key, boolean hasInitialValue, T t) {
        SavingStateLiveData<?> savingStateLiveData;
        MutableLiveData mutableLiveData = this.liveDatas.get(key);
        MutableLiveData liveData = mutableLiveData instanceof MutableLiveData ? mutableLiveData : null;
        if (liveData != null) {
            return liveData;
        }
        if (this.regular.containsKey(key)) {
            savingStateLiveData = new SavingStateLiveData<>(this, key, this.regular.get(key));
        } else if (hasInitialValue) {
            this.regular.put(key, t);
            savingStateLiveData = new SavingStateLiveData<>(this, key, t);
        } else {
            savingStateLiveData = new SavingStateLiveData<>(this, key);
        }
        this.liveDatas.put(key, savingStateLiveData);
        return savingStateLiveData;
    }

    public final <T> StateFlow<T> getStateFlow(String key, T t) {
        MutableStateFlow mutableStateFlow;
        Intrinsics.checkNotNullParameter(key, "key");
        Map $this$getOrPut$iv = this.flows;
        MutableStateFlow<Object> mutableStateFlow2 = $this$getOrPut$iv.get(key);
        if (mutableStateFlow2 == null) {
            if (!this.regular.containsKey(key)) {
                this.regular.put(key, t);
            }
            MutableStateFlow $this$getStateFlow_u24lambda_u242_u24lambda_u241 = StateFlowKt.MutableStateFlow(this.regular.get(key));
            this.flows.put(key, $this$getStateFlow_u24lambda_u242_u24lambda_u241);
            mutableStateFlow = $this$getStateFlow_u24lambda_u242_u24lambda_u241;
            $this$getOrPut$iv.put(key, mutableStateFlow);
        } else {
            mutableStateFlow = mutableStateFlow2;
        }
        StateFlow<T> asStateFlow = FlowKt.asStateFlow(mutableStateFlow);
        Intrinsics.checkNotNull(asStateFlow, "null cannot be cast to non-null type kotlinx.coroutines.flow.StateFlow<T of androidx.lifecycle.SavedStateHandle.getStateFlow>");
        return asStateFlow;
    }

    public final Set<String> keys() {
        return SetsKt.plus(SetsKt.plus((Set) this.regular.keySet(), (Iterable) this.savedStateProviders.keySet()), (Iterable) this.liveDatas.keySet());
    }

    public final <T> T get(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        try {
            return (T) this.regular.get(key);
        } catch (ClassCastException e) {
            remove(key);
            return null;
        }
    }

    public final <T> void set(String key, T t) {
        Intrinsics.checkNotNullParameter(key, "key");
        if (!Companion.validateValue(t)) {
            StringBuilder append = new StringBuilder().append("Can't put value with type ");
            Intrinsics.checkNotNull(t);
            throw new IllegalArgumentException(append.append(t.getClass()).append(" into saved state").toString());
        }
        MutableLiveData mutableLiveData = this.liveDatas.get(key);
        MutableLiveData mutableLiveData2 = mutableLiveData instanceof MutableLiveData ? mutableLiveData : null;
        if (mutableLiveData2 != null) {
            mutableLiveData2.setValue(t);
        } else {
            this.regular.put(key, t);
        }
        MutableStateFlow<Object> mutableStateFlow = this.flows.get(key);
        if (mutableStateFlow == null) {
            return;
        }
        mutableStateFlow.setValue(t);
    }

    public final <T> T remove(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        T t = (T) this.regular.remove(key);
        SavingStateLiveData liveData = this.liveDatas.remove(key);
        if (liveData != null) {
            liveData.detach();
        }
        this.flows.remove(key);
        return t;
    }

    public final void setSavedStateProvider(String key, SavedStateRegistry.SavedStateProvider provider) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(provider, "provider");
        this.savedStateProviders.put(key, provider);
    }

    public final void clearSavedStateProvider(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        this.savedStateProviders.remove(key);
    }

    /* compiled from: SavedStateHandle.kt */
    @Metadata(d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0002\b\u0003\b\u0000\u0018\u0000*\u0004\b\u0000\u0010\u00012\b\u0012\u0004\u0012\u0002H\u00010\u0002B!\b\u0016\u0012\b\u0010\u0003\u001a\u0004\u0018\u00010\u0004\u0012\u0006\u0010\u0005\u001a\u00020\u0006\u0012\u0006\u0010\u0007\u001a\u00028\u0000¢\u0006\u0002\u0010\bB\u0019\b\u0016\u0012\b\u0010\u0003\u001a\u0004\u0018\u00010\u0004\u0012\u0006\u0010\u0005\u001a\u00020\u0006¢\u0006\u0002\u0010\tJ\u0006\u0010\n\u001a\u00020\u000bJ\u0015\u0010\f\u001a\u00020\u000b2\u0006\u0010\u0007\u001a\u00028\u0000H\u0016¢\u0006\u0002\u0010\rR\u0010\u0010\u0003\u001a\u0004\u0018\u00010\u0004X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u0005\u001a\u00020\u0006X\u0082\u000e¢\u0006\u0002\n\u0000¨\u0006\u000e"}, d2 = {"Landroidx/lifecycle/SavedStateHandle$SavingStateLiveData;", "T", "Landroidx/lifecycle/MutableLiveData;", "handle", "Landroidx/lifecycle/SavedStateHandle;", "key", "", "value", "(Landroidx/lifecycle/SavedStateHandle;Ljava/lang/String;Ljava/lang/Object;)V", "(Landroidx/lifecycle/SavedStateHandle;Ljava/lang/String;)V", "detach", "", "setValue", "(Ljava/lang/Object;)V", "lifecycle-viewmodel-savedstate_release"}, k = 1, mv = {1, 8, 0}, xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
    /* loaded from: classes.dex */
    public static final class SavingStateLiveData<T> extends MutableLiveData<T> {
        private SavedStateHandle handle;
        private String key;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public SavingStateLiveData(SavedStateHandle handle, String key, T t) {
            super(t);
            Intrinsics.checkNotNullParameter(key, "key");
            this.key = key;
            this.handle = handle;
        }

        public SavingStateLiveData(SavedStateHandle handle, String key) {
            Intrinsics.checkNotNullParameter(key, "key");
            this.key = key;
            this.handle = handle;
        }

        @Override // androidx.lifecycle.MutableLiveData, androidx.lifecycle.LiveData
        public void setValue(T t) {
            SavedStateHandle it = this.handle;
            if (it != null) {
                it.regular.put(this.key, t);
                MutableStateFlow mutableStateFlow = (MutableStateFlow) it.flows.get(this.key);
                if (mutableStateFlow != null) {
                    mutableStateFlow.setValue(t);
                }
            }
            super.setValue(t);
        }

        public final void detach() {
            this.handle = null;
        }
    }

    /* compiled from: SavedStateHandle.kt */
    @Metadata(d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0002\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002J\u001c\u0010\n\u001a\u00020\u000b2\b\u0010\f\u001a\u0004\u0018\u00010\r2\b\u0010\u000e\u001a\u0004\u0018\u00010\rH\u0007J\u0012\u0010\u000f\u001a\u00020\u00102\b\u0010\u0011\u001a\u0004\u0018\u00010\u0001H\u0007R \u0010\u0003\u001a\u0012\u0012\u000e\u0012\f\u0012\u0006\b\u0001\u0012\u00020\u0001\u0018\u00010\u00050\u0004X\u0082\u0004¢\u0006\u0004\n\u0002\u0010\u0006R\u000e\u0010\u0007\u001a\u00020\bX\u0082T¢\u0006\u0002\n\u0000R\u000e\u0010\t\u001a\u00020\bX\u0082T¢\u0006\u0002\n\u0000¨\u0006\u0012"}, d2 = {"Landroidx/lifecycle/SavedStateHandle$Companion;", "", "()V", "ACCEPTABLE_CLASSES", "", "Ljava/lang/Class;", "[Ljava/lang/Class;", "KEYS", "", "VALUES", "createHandle", "Landroidx/lifecycle/SavedStateHandle;", "restoredState", "Landroid/os/Bundle;", "defaultState", "validateValue", "", "value", "lifecycle-viewmodel-savedstate_release"}, k = 1, mv = {1, 8, 0}, xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
    /* loaded from: classes.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        @JvmStatic
        public final SavedStateHandle createHandle(Bundle restoredState, Bundle defaultState) {
            if (restoredState == null) {
                if (defaultState == null) {
                    return new SavedStateHandle();
                }
                Map state = new HashMap();
                for (String key : defaultState.keySet()) {
                    Intrinsics.checkNotNullExpressionValue(key, "key");
                    state.put(key, defaultState.get(key));
                }
                return new SavedStateHandle(state);
            }
            ArrayList keys = restoredState.getParcelableArrayList(SavedStateHandle.KEYS);
            ArrayList values = restoredState.getParcelableArrayList(SavedStateHandle.VALUES);
            if (!((keys == null || values == null || keys.size() != values.size()) ? false : true)) {
                throw new IllegalStateException("Invalid bundle passed as restored state".toString());
            }
            Map state2 = new LinkedHashMap();
            int size = keys.size();
            for (int i = 0; i < size; i++) {
                Object obj = keys.get(i);
                Intrinsics.checkNotNull(obj, "null cannot be cast to non-null type kotlin.String");
                state2.put((String) obj, values.get(i));
            }
            return new SavedStateHandle(state2);
        }

        public final boolean validateValue(Object value) {
            Class[] clsArr;
            if (value != null) {
                for (Class cl : SavedStateHandle.ACCEPTABLE_CLASSES) {
                    Intrinsics.checkNotNull(cl);
                    if (cl.isInstance(value)) {
                        return true;
                    }
                }
                return false;
            }
            return true;
        }
    }
}
