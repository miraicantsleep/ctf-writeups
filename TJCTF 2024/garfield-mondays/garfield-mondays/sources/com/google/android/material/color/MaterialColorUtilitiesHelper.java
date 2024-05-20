package com.google.android.material.color;

import com.google.android.material.R;
import com.google.android.material.color.utilities.DynamicColor;
import com.google.android.material.color.utilities.DynamicScheme;
import com.google.android.material.color.utilities.MaterialDynamicColors;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
public final class MaterialColorUtilitiesHelper {
    private static final Map<Integer, DynamicColor> colorResourceIdToColorValue;
    private static final MaterialDynamicColors dynamicColors = new MaterialDynamicColors();

    private MaterialColorUtilitiesHelper() {
    }

    static {
        Map<Integer, DynamicColor> map = new HashMap<>();
        map.put(Integer.valueOf(R.color.material_personalized_color_primary), dynamicColors.primary());
        map.put(Integer.valueOf(R.color.material_personalized_color_on_primary), dynamicColors.onPrimary());
        map.put(Integer.valueOf(R.color.material_personalized_color_primary_inverse), dynamicColors.inversePrimary());
        map.put(Integer.valueOf(R.color.material_personalized_color_primary_container), dynamicColors.primaryContainer());
        map.put(Integer.valueOf(R.color.material_personalized_color_on_primary_container), dynamicColors.onPrimaryContainer());
        map.put(Integer.valueOf(R.color.material_personalized_color_secondary), dynamicColors.secondary());
        map.put(Integer.valueOf(R.color.material_personalized_color_on_secondary), dynamicColors.onSecondary());
        map.put(Integer.valueOf(R.color.material_personalized_color_secondary_container), dynamicColors.secondaryContainer());
        map.put(Integer.valueOf(R.color.material_personalized_color_on_secondary_container), dynamicColors.onSecondaryContainer());
        map.put(Integer.valueOf(R.color.material_personalized_color_tertiary), dynamicColors.tertiary());
        map.put(Integer.valueOf(R.color.material_personalized_color_on_tertiary), dynamicColors.onTertiary());
        map.put(Integer.valueOf(R.color.material_personalized_color_tertiary_container), dynamicColors.tertiaryContainer());
        map.put(Integer.valueOf(R.color.material_personalized_color_on_tertiary_container), dynamicColors.onTertiaryContainer());
        map.put(Integer.valueOf(R.color.material_personalized_color_background), dynamicColors.background());
        map.put(Integer.valueOf(R.color.material_personalized_color_on_background), dynamicColors.onBackground());
        map.put(Integer.valueOf(R.color.material_personalized_color_surface), dynamicColors.surface());
        map.put(Integer.valueOf(R.color.material_personalized_color_on_surface), dynamicColors.onSurface());
        map.put(Integer.valueOf(R.color.material_personalized_color_surface_variant), dynamicColors.surfaceVariant());
        map.put(Integer.valueOf(R.color.material_personalized_color_on_surface_variant), dynamicColors.onSurfaceVariant());
        map.put(Integer.valueOf(R.color.material_personalized_color_surface_inverse), dynamicColors.inverseSurface());
        map.put(Integer.valueOf(R.color.material_personalized_color_on_surface_inverse), dynamicColors.inverseOnSurface());
        map.put(Integer.valueOf(R.color.material_personalized_color_surface_bright), dynamicColors.surfaceBright());
        map.put(Integer.valueOf(R.color.material_personalized_color_surface_dim), dynamicColors.surfaceDim());
        map.put(Integer.valueOf(R.color.material_personalized_color_surface_container), dynamicColors.surfaceContainer());
        map.put(Integer.valueOf(R.color.material_personalized_color_surface_container_low), dynamicColors.surfaceContainerLow());
        map.put(Integer.valueOf(R.color.material_personalized_color_surface_container_high), dynamicColors.surfaceContainerHigh());
        map.put(Integer.valueOf(R.color.material_personalized_color_surface_container_lowest), dynamicColors.surfaceContainerLowest());
        map.put(Integer.valueOf(R.color.material_personalized_color_surface_container_highest), dynamicColors.surfaceContainerHighest());
        map.put(Integer.valueOf(R.color.material_personalized_color_outline), dynamicColors.outline());
        map.put(Integer.valueOf(R.color.material_personalized_color_outline_variant), dynamicColors.outlineVariant());
        map.put(Integer.valueOf(R.color.material_personalized_color_error), dynamicColors.error());
        map.put(Integer.valueOf(R.color.material_personalized_color_on_error), dynamicColors.onError());
        map.put(Integer.valueOf(R.color.material_personalized_color_error_container), dynamicColors.errorContainer());
        map.put(Integer.valueOf(R.color.material_personalized_color_on_error_container), dynamicColors.onErrorContainer());
        map.put(Integer.valueOf(R.color.material_personalized_color_control_activated), dynamicColors.controlActivated());
        map.put(Integer.valueOf(R.color.material_personalized_color_control_normal), dynamicColors.controlNormal());
        map.put(Integer.valueOf(R.color.material_personalized_color_control_highlight), dynamicColors.controlHighlight());
        map.put(Integer.valueOf(R.color.material_personalized_color_text_primary_inverse), dynamicColors.textPrimaryInverse());
        map.put(Integer.valueOf(R.color.material_personalized_color_text_secondary_and_tertiary_inverse), dynamicColors.textSecondaryAndTertiaryInverse());
        map.put(Integer.valueOf(R.color.material_personalized_color_text_secondary_and_tertiary_inverse_disabled), dynamicColors.textSecondaryAndTertiaryInverseDisabled());
        map.put(Integer.valueOf(R.color.material_personalized_color_text_primary_inverse_disable_only), dynamicColors.textPrimaryInverseDisableOnly());
        map.put(Integer.valueOf(R.color.material_personalized_color_text_hint_foreground_inverse), dynamicColors.textHintInverse());
        colorResourceIdToColorValue = Collections.unmodifiableMap(map);
    }

    public static Map<Integer, Integer> createColorResourcesIdsToColorValues(DynamicScheme colorScheme) {
        HashMap<Integer, Integer> map = new HashMap<>();
        for (Map.Entry<Integer, DynamicColor> entry : colorResourceIdToColorValue.entrySet()) {
            map.put(entry.getKey(), Integer.valueOf(entry.getValue().getArgb(colorScheme)));
        }
        return Collections.unmodifiableMap(map);
    }
}
