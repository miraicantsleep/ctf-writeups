package androidx.core.graphics;

import android.graphics.Typeface;
import android.util.Log;
import android.util.SparseArray;
import androidx.collection.LongSparseArray;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
/* loaded from: classes.dex */
final class WeightTypefaceApi21 {
    private static final String NATIVE_CREATE_FROM_TYPEFACE_METHOD = "nativeCreateFromTypeface";
    private static final String NATIVE_CREATE_WEIGHT_ALIAS_METHOD = "nativeCreateWeightAlias";
    private static final String NATIVE_INSTANCE_FIELD = "native_instance";
    private static final String TAG = "WeightTypeface";
    private static final Constructor<Typeface> sConstructor;
    private static final Method sNativeCreateFromTypeface;
    private static final Method sNativeCreateWeightAlias;
    private static final Field sNativeInstance;
    private static final Object sWeightCacheLock;
    private static final LongSparseArray<SparseArray<Typeface>> sWeightTypefaceCache;

    static {
        Field nativeInstance;
        Method nativeCreateFromTypeface;
        Method nativeCreateWeightAlias;
        Constructor<Typeface> constructor;
        try {
            nativeInstance = Typeface.class.getDeclaredField(NATIVE_INSTANCE_FIELD);
            nativeCreateFromTypeface = Typeface.class.getDeclaredMethod(NATIVE_CREATE_FROM_TYPEFACE_METHOD, Long.TYPE, Integer.TYPE);
            nativeCreateFromTypeface.setAccessible(true);
            nativeCreateWeightAlias = Typeface.class.getDeclaredMethod(NATIVE_CREATE_WEIGHT_ALIAS_METHOD, Long.TYPE, Integer.TYPE);
            nativeCreateWeightAlias.setAccessible(true);
            constructor = Typeface.class.getDeclaredConstructor(Long.TYPE);
            constructor.setAccessible(true);
        } catch (NoSuchFieldException | NoSuchMethodException e) {
            Log.e(TAG, e.getClass().getName(), e);
            nativeInstance = null;
            nativeCreateFromTypeface = null;
            nativeCreateWeightAlias = null;
            constructor = null;
        }
        sNativeInstance = nativeInstance;
        sNativeCreateFromTypeface = nativeCreateFromTypeface;
        sNativeCreateWeightAlias = nativeCreateWeightAlias;
        sConstructor = constructor;
        sWeightTypefaceCache = new LongSparseArray<>(3);
        sWeightCacheLock = new Object();
    }

    private static boolean isPrivateApiAvailable() {
        return sNativeInstance != null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static Typeface createWeightStyle(Typeface base, int weight, boolean italic) {
        Typeface typeface;
        if (!isPrivateApiAvailable()) {
            return null;
        }
        int key = (weight << 1) | italic;
        synchronized (sWeightCacheLock) {
            long baseNativeInstance = getNativeInstance(base);
            SparseArray<Typeface> innerCache = sWeightTypefaceCache.get(baseNativeInstance);
            if (innerCache == null) {
                innerCache = new SparseArray<>(4);
                sWeightTypefaceCache.put(baseNativeInstance, innerCache);
            } else {
                Typeface typeface2 = innerCache.get(key);
                if (typeface2 != null) {
                    return typeface2;
                }
            }
            if (italic == base.isItalic()) {
                typeface = create(nativeCreateWeightAlias(baseNativeInstance, weight));
            } else {
                typeface = create(nativeCreateFromTypefaceWithExactStyle(baseNativeInstance, weight, italic));
            }
            innerCache.put(key, typeface);
            return typeface;
        }
    }

    private static long getNativeInstance(Typeface typeface) {
        try {
            return sNativeInstance.getLong(typeface);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    private static long nativeCreateFromTypefaceWithExactStyle(long nativeInstance, int weight, boolean italic) {
        int style = italic ? 2 : 0;
        try {
            return ((Long) sNativeCreateWeightAlias.invoke(null, Long.valueOf(((Long) sNativeCreateFromTypeface.invoke(null, Long.valueOf(nativeInstance), Integer.valueOf(style))).longValue()), Integer.valueOf(weight))).longValue();
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e2) {
            throw new RuntimeException(e2);
        }
    }

    private static long nativeCreateWeightAlias(long nativeInstance, int weight) {
        try {
            return ((Long) sNativeCreateWeightAlias.invoke(null, Long.valueOf(nativeInstance), Integer.valueOf(weight))).longValue();
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e2) {
            throw new RuntimeException(e2);
        }
    }

    private static Typeface create(long nativeInstance) {
        try {
            return sConstructor.newInstance(Long.valueOf(nativeInstance));
        } catch (IllegalAccessException e) {
            return null;
        } catch (InstantiationException e2) {
            return null;
        } catch (InvocationTargetException e3) {
            return null;
        }
    }

    private WeightTypefaceApi21() {
    }
}
