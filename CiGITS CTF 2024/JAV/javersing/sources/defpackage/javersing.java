package defpackage;

import java.util.Scanner;

/* loaded from: javersing.jar:javersing.class */
public class javersing {
    public static void main(String[] strArr) {
        boolean z = true;
        Scanner scanner = new Scanner(System.in);
        System.out.println("Input password: ");
        String replace = String.format("%30s", scanner.nextLine()).replace(" ", "0");
        for (int i = 0; i < 30; i++) {
            if (replace.charAt((i * 7) % 30) != "Fcn_yDlvaGpj_Logi}eias{iaeAm_s".charAt(i)) {
                z = false;
            }
        }
        if (z) {
            System.out.println("Correct!");
        } else {
            System.out.println("Incorrect...");
        }
    }
}
