package com.google.android.material.color;

import android.content.Context;
import android.content.res.loader.ResourcesLoader;
import java.util.Map;
/* loaded from: classes.dex */
final class ResourcesLoaderUtils {
    private ResourcesLoaderUtils() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean addResourcesLoaderToContext(Context context, Map<Integer, Integer> colorReplacementMap) {
        ResourcesLoader resourcesLoader = ColorResourcesLoaderCreator.create(context, colorReplacementMap);
        if (resourcesLoader == null) {
            return false;
        }
        context.getResources().addLoaders(resourcesLoader);
        return true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isColorResource(int attrType) {
        return 28 <= attrType && attrType <= 31;
    }
}
