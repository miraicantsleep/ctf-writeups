package com.google.errorprone.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Target;
@Target({ElementType.METHOD, ElementType.CONSTRUCTOR})
/* loaded from: classes.dex */
public @interface InlineMeValidationDisabled {
    String value();
}
