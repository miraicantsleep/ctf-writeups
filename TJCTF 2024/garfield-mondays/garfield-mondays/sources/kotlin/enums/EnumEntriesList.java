package kotlin.enums;

import androidx.constraintlayout.widget.ConstraintLayout;
import java.io.Serializable;
import java.lang.Enum;
import kotlin.Metadata;
import kotlin.collections.AbstractList;
import kotlin.collections.ArraysKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
/* compiled from: EnumEntries.kt */
@Metadata(d1 = {"\u0000>\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0010\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0011\n\u0002\b\u0007\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\t\n\u0002\u0010\u0000\n\u0000\b\u0003\u0018\u0000*\u000e\b\u0000\u0010\u0001*\b\u0012\u0004\u0012\u0002H\u00010\u00022\b\u0012\u0004\u0012\u0002H\u00010\u00032\b\u0012\u0004\u0012\u0002H\u00010\u00042\u00060\u0005j\u0002`\u0006B\u0019\u0012\u0012\u0010\u0007\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00028\u00000\t0\b¢\u0006\u0002\u0010\nJ\u0016\u0010\u0014\u001a\u00020\u00152\u0006\u0010\u0016\u001a\u00028\u0000H\u0096\u0002¢\u0006\u0002\u0010\u0017J\u0016\u0010\u0018\u001a\u00028\u00002\u0006\u0010\u0019\u001a\u00020\u0011H\u0096\u0002¢\u0006\u0002\u0010\u001aJ\u0015\u0010\u001b\u001a\u00020\u00112\u0006\u0010\u0016\u001a\u00028\u0000H\u0016¢\u0006\u0002\u0010\u001cJ\u0015\u0010\u001d\u001a\u00020\u00112\u0006\u0010\u0016\u001a\u00028\u0000H\u0016¢\u0006\u0002\u0010\u001cJ\b\u0010\u001e\u001a\u00020\u001fH\u0002R\u0018\u0010\u000b\u001a\n\u0012\u0004\u0012\u00028\u0000\u0018\u00010\tX\u0082\u000e¢\u0006\u0004\n\u0002\u0010\fR\u001a\u0010\r\u001a\b\u0012\u0004\u0012\u00028\u00000\t8BX\u0082\u0004¢\u0006\u0006\u001a\u0004\b\u000e\u0010\u000fR\u001a\u0010\u0007\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00028\u00000\t0\bX\u0082\u0004¢\u0006\u0002\n\u0000R\u0014\u0010\u0010\u001a\u00020\u00118VX\u0096\u0004¢\u0006\u0006\u001a\u0004\b\u0012\u0010\u0013¨\u0006 "}, d2 = {"Lkotlin/enums/EnumEntriesList;", "T", "", "Lkotlin/enums/EnumEntries;", "Lkotlin/collections/AbstractList;", "Ljava/io/Serializable;", "Lkotlin/io/Serializable;", "entriesProvider", "Lkotlin/Function0;", "", "(Lkotlin/jvm/functions/Function0;)V", "_entries", "[Ljava/lang/Enum;", "entries", "getEntries", "()[Ljava/lang/Enum;", "size", "", "getSize", "()I", "contains", "", "element", "(Ljava/lang/Enum;)Z", "get", "index", "(I)Ljava/lang/Enum;", "indexOf", "(Ljava/lang/Enum;)I", "lastIndexOf", "writeReplace", "", "kotlin-stdlib"}, k = 1, mv = {1, 8, 0}, xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes.dex */
final class EnumEntriesList<T extends Enum<T>> extends AbstractList<T> implements EnumEntries<T>, Serializable {
    private volatile T[] _entries;
    private final Function0<T[]> entriesProvider;

    /* JADX WARN: Multi-variable type inference failed */
    @Override // kotlin.collections.AbstractCollection, java.util.Collection
    public final /* bridge */ boolean contains(Object element) {
        if (element instanceof Enum) {
            return contains((EnumEntriesList<T>) ((Enum) element));
        }
        return false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // kotlin.collections.AbstractList, java.util.List
    public final /* bridge */ int indexOf(Object element) {
        if (element instanceof Enum) {
            return indexOf((EnumEntriesList<T>) ((Enum) element));
        }
        return -1;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // kotlin.collections.AbstractList, java.util.List
    public final /* bridge */ int lastIndexOf(Object element) {
        if (element instanceof Enum) {
            return lastIndexOf((EnumEntriesList<T>) ((Enum) element));
        }
        return -1;
    }

    public EnumEntriesList(Function0<T[]> entriesProvider) {
        Intrinsics.checkNotNullParameter(entriesProvider, "entriesProvider");
        this.entriesProvider = entriesProvider;
    }

    private final T[] getEntries() {
        T[] tArr = this._entries;
        if (tArr != null) {
            return tArr;
        }
        Enum[] e = this.entriesProvider.invoke();
        Enum[] enumArr = e;
        this._entries = enumArr;
        return enumArr;
    }

    @Override // kotlin.collections.AbstractList, kotlin.collections.AbstractCollection
    public int getSize() {
        return getEntries().length;
    }

    @Override // kotlin.collections.AbstractList, java.util.List
    public T get(int index) {
        T[] entries = getEntries();
        AbstractList.Companion.checkElementIndex$kotlin_stdlib(index, entries.length);
        return entries[index];
    }

    public boolean contains(T element) {
        Intrinsics.checkNotNullParameter(element, "element");
        Enum target = (Enum) ArraysKt.getOrNull(getEntries(), element.ordinal());
        return target == element;
    }

    public int indexOf(T element) {
        Intrinsics.checkNotNullParameter(element, "element");
        int ordinal = element.ordinal();
        Enum target = (Enum) ArraysKt.getOrNull(getEntries(), ordinal);
        if (target == element) {
            return ordinal;
        }
        return -1;
    }

    public int lastIndexOf(T element) {
        Intrinsics.checkNotNullParameter(element, "element");
        return indexOf((Object) element);
    }

    private final Object writeReplace() {
        return new EnumEntriesSerializationProxy(getEntries());
    }
}
