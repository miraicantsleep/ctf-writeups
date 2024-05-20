package androidx.profileinstaller;

import android.content.Context;
import androidx.profileinstaller.ProfileInstallReceiver;
import java.io.File;
/* loaded from: classes.dex */
class BenchmarkOperation {
    private BenchmarkOperation() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void dropShaderCache(Context context, ProfileInstallReceiver.ResultDiagnostics callback) {
        File shaderDirectory = Api24ContextHelper.getDeviceProtectedCodeCacheDir(context);
        if (deleteFilesRecursively(shaderDirectory)) {
            callback.onResultReceived(14, null);
        } else {
            callback.onResultReceived(15, null);
        }
    }

    static boolean deleteFilesRecursively(File file) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children == null) {
                return false;
            }
            boolean success = true;
            for (File child : children) {
                success = deleteFilesRecursively(child) && success;
            }
            return success;
        }
        file.delete();
        return true;
    }

    /* loaded from: classes.dex */
    private static class Api21ContextHelper {
        private Api21ContextHelper() {
        }

        static File getCodeCacheDir(Context context) {
            return context.getCodeCacheDir();
        }
    }

    /* loaded from: classes.dex */
    private static class Api24ContextHelper {
        private Api24ContextHelper() {
        }

        static File getDeviceProtectedCodeCacheDir(Context context) {
            return context.createDeviceProtectedStorageContext().getCodeCacheDir();
        }
    }
}
