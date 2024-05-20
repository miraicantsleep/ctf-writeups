package com.tjctf.garfieldmondays;

import androidx.constraintlayout.widget.ConstraintLayout;
/* loaded from: classes3.dex */
public class TimeEncoder {
    public static String encodeTime(String time) {
        char[] charArray;
        StringBuilder encoded = new StringBuilder();
        for (char c : time.toCharArray()) {
            encoded.append(mapCharacter(c));
        }
        return encoded.toString();
    }

    private static String mapCharacter(char c) {
        switch (c) {
            case '(':
                return "46";
            case '*':
                return "!";
            case ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE /* 48 */:
                return "4";
            case ConstraintLayout.LayoutParams.Table.LAYOUT_EDITOR_ABSOLUTEX /* 49 */:
                return "g";
            case '2':
                return "i";
            case ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_TAG /* 51 */:
                return "l";
            case ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_BASELINE_TO_TOP_OF /* 52 */:
                return "f";
            case ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_BASELINE_TO_BOTTOM_OF /* 53 */:
                return "e";
            case ConstraintLayout.LayoutParams.Table.LAYOUT_MARGIN_BASELINE /* 54 */:
                return "d";
            case ConstraintLayout.LayoutParams.Table.LAYOUT_GONE_MARGIN_BASELINE /* 55 */:
                return "1";
            case '8':
                return "2";
            case '9':
                return "3";
            case 'a':
                return "j";
            case 'b':
                return "c";
            case 'j':
                return "k";
            case 'n':
                return "v";
            case 'o':
                return "w";
            case 'q':
                return "w";
            case 'z':
                return "2";
            case '}':
                return "{";
            default:
                return "";
        }
    }
}
