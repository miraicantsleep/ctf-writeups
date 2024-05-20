package androidx.core.os;

import android.os.Parcel;
import android.os.Parcelable;
import android.util.SparseArray;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
/* loaded from: classes.dex */
public final class ParcelCompat {
    public static boolean readBoolean(Parcel in) {
        return in.readInt() != 0;
    }

    public static void writeBoolean(Parcel out, boolean value) {
        out.writeInt(value ? 1 : 0);
    }

    public static <T> void readList(Parcel in, List<? super T> outVal, ClassLoader loader, Class<T> clazz) {
        if (BuildCompat.isAtLeastT()) {
            TiramisuImpl.readList(in, outVal, loader, clazz);
        } else {
            in.readList(outVal, loader);
        }
    }

    public static <T> ArrayList<T> readArrayList(Parcel in, ClassLoader loader, Class<? extends T> clazz) {
        if (BuildCompat.isAtLeastT()) {
            return TiramisuImpl.readArrayList(in, loader, clazz);
        }
        return in.readArrayList(loader);
    }

    public static <T> T[] readArray(Parcel in, ClassLoader loader, Class<T> clazz) {
        if (BuildCompat.isAtLeastT()) {
            return (T[]) TiramisuImpl.readArray(in, loader, clazz);
        }
        return (T[]) in.readArray(loader);
    }

    public static <T> SparseArray<T> readSparseArray(Parcel in, ClassLoader loader, Class<? extends T> clazz) {
        if (BuildCompat.isAtLeastT()) {
            return TiramisuImpl.readSparseArray(in, loader, clazz);
        }
        return in.readSparseArray(loader);
    }

    public static <K, V> void readMap(Parcel in, Map<? super K, ? super V> outVal, ClassLoader loader, Class<K> clazzKey, Class<V> clazzValue) {
        if (BuildCompat.isAtLeastT()) {
            TiramisuImpl.readMap(in, outVal, loader, clazzKey, clazzValue);
        } else {
            in.readMap(outVal, loader);
        }
    }

    public static <K, V> HashMap<K, V> readHashMap(Parcel in, ClassLoader loader, Class<? extends K> clazzKey, Class<? extends V> clazzValue) {
        if (BuildCompat.isAtLeastT()) {
            return TiramisuImpl.readHashMap(in, loader, clazzKey, clazzValue);
        }
        return in.readHashMap(loader);
    }

    public static <T extends Parcelable> T readParcelable(Parcel in, ClassLoader loader, Class<T> clazz) {
        if (BuildCompat.isAtLeastT()) {
            return (T) TiramisuImpl.readParcelable(in, loader, clazz);
        }
        return (T) in.readParcelable(loader);
    }

    public static <T> Parcelable.Creator<T> readParcelableCreator(Parcel in, ClassLoader loader, Class<T> clazz) {
        if (BuildCompat.isAtLeastT()) {
            return TiramisuImpl.readParcelableCreator(in, loader, clazz);
        }
        return (Parcelable.Creator<T>) Api30Impl.readParcelableCreator(in, loader);
    }

    public static <T> T[] readParcelableArray(Parcel in, ClassLoader loader, Class<T> clazz) {
        if (BuildCompat.isAtLeastT()) {
            return (T[]) TiramisuImpl.readParcelableArray(in, loader, clazz);
        }
        return (T[]) in.readParcelableArray(loader);
    }

    public static <T> List<T> readParcelableList(Parcel in, List<T> list, ClassLoader cl, Class<T> clazz) {
        if (BuildCompat.isAtLeastT()) {
            return TiramisuImpl.readParcelableList(in, list, cl, clazz);
        }
        return Api29Impl.readParcelableList(in, list, cl);
    }

    public static <T extends Serializable> T readSerializable(Parcel in, ClassLoader loader, Class<T> clazz) {
        if (BuildCompat.isAtLeastT()) {
            return (T) TiramisuImpl.readSerializable(in, loader, clazz);
        }
        return (T) in.readSerializable();
    }

    private ParcelCompat() {
    }

    /* loaded from: classes.dex */
    static class Api29Impl {
        private Api29Impl() {
        }

        static final <T extends Parcelable> List<T> readParcelableList(Parcel in, List<T> list, ClassLoader cl) {
            return in.readParcelableList(list, cl);
        }
    }

    /* loaded from: classes.dex */
    static class Api30Impl {
        private Api30Impl() {
        }

        static final Parcelable.Creator<?> readParcelableCreator(Parcel in, ClassLoader loader) {
            return in.readParcelableCreator(loader);
        }
    }

    /* loaded from: classes.dex */
    static class TiramisuImpl {
        private TiramisuImpl() {
        }

        static <T extends Serializable> T readSerializable(Parcel in, ClassLoader loader, Class<T> clazz) {
            return (T) in.readSerializable(loader, clazz);
        }

        static <T extends Parcelable> T readParcelable(Parcel in, ClassLoader loader, Class<T> clazz) {
            return (T) in.readParcelable(loader, clazz);
        }

        public static <T> Parcelable.Creator<T> readParcelableCreator(Parcel in, ClassLoader loader, Class<T> clazz) {
            return in.readParcelableCreator(loader, clazz);
        }

        static <T> T[] readParcelableArray(Parcel in, ClassLoader loader, Class<T> clazz) {
            return (T[]) in.readParcelableArray(loader, clazz);
        }

        static <T> List<T> readParcelableList(Parcel in, List<T> list, ClassLoader cl, Class<T> clazz) {
            return in.readParcelableList(list, cl, clazz);
        }

        public static <T> void readList(Parcel in, List<? super T> outVal, ClassLoader loader, Class<T> clazz) {
            in.readList(outVal, loader, clazz);
        }

        public static <T> ArrayList<T> readArrayList(Parcel in, ClassLoader loader, Class<? extends T> clazz) {
            return in.readArrayList(loader, clazz);
        }

        public static <T> T[] readArray(Parcel in, ClassLoader loader, Class<T> clazz) {
            return (T[]) in.readArray(loader, clazz);
        }

        public static <T> SparseArray<T> readSparseArray(Parcel in, ClassLoader loader, Class<? extends T> clazz) {
            return in.readSparseArray(loader, clazz);
        }

        public static <K, V> void readMap(Parcel in, Map<? super K, ? super V> outVal, ClassLoader loader, Class<K> clazzKey, Class<V> clazzValue) {
            in.readMap(outVal, loader, clazzKey, clazzValue);
        }

        public static <V, K> HashMap<K, V> readHashMap(Parcel in, ClassLoader loader, Class<? extends K> clazzKey, Class<? extends V> clazzValue) {
            return in.readHashMap(loader, clazzKey, clazzValue);
        }
    }
}
