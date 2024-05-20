package androidx.profileinstaller;

import android.content.res.AssetFileDescriptor;
import android.content.res.AssetManager;
import android.os.Build;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.profileinstaller.ProfileInstaller;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.Executor;
/* loaded from: classes.dex */
public class DeviceProfileWriter {
    private final String mApkName;
    private final AssetManager mAssetManager;
    private final File mCurProfile;
    private final ProfileInstaller.DiagnosticsCallback mDiagnostics;
    private final Executor mExecutor;
    private DexProfileData[] mProfile;
    private final String mProfileMetaSourceLocation;
    private final String mProfileSourceLocation;
    private byte[] mTranscodedProfile;
    private boolean mDeviceSupportsAotProfile = false;
    private final byte[] mDesiredVersion = desiredVersion();

    private void result(final int code, final Object data) {
        this.mExecutor.execute(new Runnable() { // from class: androidx.profileinstaller.DeviceProfileWriter$$ExternalSyntheticLambda0
            @Override // java.lang.Runnable
            public final void run() {
                DeviceProfileWriter.this.m45lambda$result$0$androidxprofileinstallerDeviceProfileWriter(code, data);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$result$0$androidx-profileinstaller-DeviceProfileWriter  reason: not valid java name */
    public /* synthetic */ void m45lambda$result$0$androidxprofileinstallerDeviceProfileWriter(int code, Object data) {
        this.mDiagnostics.onResultReceived(code, data);
    }

    public DeviceProfileWriter(AssetManager assetManager, Executor executor, ProfileInstaller.DiagnosticsCallback diagnosticsCallback, String apkName, String profileSourceLocation, String profileMetaSourceLocation, File curProfile) {
        this.mAssetManager = assetManager;
        this.mExecutor = executor;
        this.mDiagnostics = diagnosticsCallback;
        this.mApkName = apkName;
        this.mProfileSourceLocation = profileSourceLocation;
        this.mProfileMetaSourceLocation = profileMetaSourceLocation;
        this.mCurProfile = curProfile;
    }

    public boolean deviceAllowsProfileInstallerAotWrites() {
        if (this.mDesiredVersion == null) {
            result(3, Integer.valueOf(Build.VERSION.SDK_INT));
            return false;
        } else if (!this.mCurProfile.canWrite()) {
            result(4, null);
            return false;
        } else {
            this.mDeviceSupportsAotProfile = true;
            return true;
        }
    }

    private void assertDeviceAllowsProfileInstallerAotWritesCalled() {
        if (!this.mDeviceSupportsAotProfile) {
            throw new IllegalStateException("This device doesn't support aot. Did you call deviceSupportsAotProfile()?");
        }
    }

    public DeviceProfileWriter read() {
        DeviceProfileWriter profileWriter;
        assertDeviceAllowsProfileInstallerAotWritesCalled();
        if (this.mDesiredVersion == null) {
            return this;
        }
        InputStream profileStream = getProfileInputStream(this.mAssetManager);
        if (profileStream != null) {
            this.mProfile = readProfileInternal(profileStream);
        }
        if (this.mProfile != null) {
            DexProfileData[] profile = this.mProfile;
            if (requiresMetadata() && (profileWriter = addMetadata(profile, this.mDesiredVersion)) != null) {
                return profileWriter;
            }
        }
        return this;
    }

    private InputStream openStreamFromAssets(AssetManager assetManager, String location) throws IOException {
        try {
            AssetFileDescriptor descriptor = assetManager.openFd(location);
            InputStream profileStream = descriptor.createInputStream();
            return profileStream;
        } catch (FileNotFoundException e) {
            String message = e.getMessage();
            if (message == null || !message.contains("compressed")) {
                return null;
            }
            this.mDiagnostics.onDiagnosticReceived(5, null);
            return null;
        }
    }

    private InputStream getProfileInputStream(AssetManager assetManager) {
        try {
            InputStream profileStream = openStreamFromAssets(assetManager, this.mProfileSourceLocation);
            return profileStream;
        } catch (FileNotFoundException e) {
            this.mDiagnostics.onResultReceived(6, e);
            return null;
        } catch (IOException e2) {
            this.mDiagnostics.onResultReceived(7, e2);
            return null;
        }
    }

    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:8:0x0014 -> B:19:0x0032). Please submit an issue!!! */
    private DexProfileData[] readProfileInternal(InputStream profileStream) {
        DexProfileData[] profile = null;
        try {
            try {
                try {
                    byte[] baselineVersion = ProfileTranscoder.readHeader(profileStream, ProfileTranscoder.MAGIC_PROF);
                    profile = ProfileTranscoder.readProfile(profileStream, baselineVersion, this.mApkName);
                    profileStream.close();
                } catch (IOException e) {
                    this.mDiagnostics.onResultReceived(7, e);
                }
            } catch (IOException e2) {
                this.mDiagnostics.onResultReceived(7, e2);
                profileStream.close();
            } catch (IllegalStateException e3) {
                this.mDiagnostics.onResultReceived(8, e3);
                profileStream.close();
            }
            return profile;
        } catch (Throwable th) {
            try {
                profileStream.close();
            } catch (IOException e4) {
                this.mDiagnostics.onResultReceived(7, e4);
            }
            throw th;
        }
    }

    private DeviceProfileWriter addMetadata(DexProfileData[] profile, byte[] desiredVersion) {
        InputStream is;
        try {
            is = openStreamFromAssets(this.mAssetManager, this.mProfileMetaSourceLocation);
        } catch (FileNotFoundException e) {
            this.mDiagnostics.onResultReceived(9, e);
        } catch (IOException e2) {
            this.mDiagnostics.onResultReceived(7, e2);
        } catch (IllegalStateException e3) {
            this.mProfile = null;
            this.mDiagnostics.onResultReceived(8, e3);
        }
        if (is != null) {
            try {
                byte[] metaVersion = ProfileTranscoder.readHeader(is, ProfileTranscoder.MAGIC_PROFM);
                this.mProfile = ProfileTranscoder.readMeta(is, metaVersion, desiredVersion, profile);
                if (is != null) {
                    is.close();
                }
                return this;
            } catch (Throwable th) {
                if (is != null) {
                    try {
                        is.close();
                    } catch (Throwable th2) {
                        th.addSuppressed(th2);
                    }
                }
                throw th;
            }
        }
        if (is != null) {
            is.close();
        }
        return null;
    }

    public DeviceProfileWriter transcodeIfNeeded() {
        ByteArrayOutputStream os;
        boolean success;
        DexProfileData[] profile = this.mProfile;
        byte[] desiredVersion = this.mDesiredVersion;
        if (profile == null || desiredVersion == null) {
            return this;
        }
        assertDeviceAllowsProfileInstallerAotWritesCalled();
        try {
            os = new ByteArrayOutputStream();
            try {
                ProfileTranscoder.writeHeader(os, desiredVersion);
                success = ProfileTranscoder.transcodeAndWriteBody(os, desiredVersion, profile);
            } catch (Throwable th) {
                try {
                    os.close();
                } catch (Throwable th2) {
                    th.addSuppressed(th2);
                }
                throw th;
            }
        } catch (IOException e) {
            this.mDiagnostics.onResultReceived(7, e);
        } catch (IllegalStateException e2) {
            this.mDiagnostics.onResultReceived(8, e2);
        }
        if (!success) {
            this.mDiagnostics.onResultReceived(5, null);
            this.mProfile = null;
            os.close();
            return this;
        }
        this.mTranscodedProfile = os.toByteArray();
        os.close();
        this.mProfile = null;
        return this;
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [androidx.profileinstaller.DexProfileData[], byte[]] */
    public boolean write() {
        byte[] transcodedProfile = this.mTranscodedProfile;
        if (transcodedProfile == null) {
            return false;
        }
        assertDeviceAllowsProfileInstallerAotWritesCalled();
        try {
            try {
                InputStream bis = new ByteArrayInputStream(transcodedProfile);
                try {
                    OutputStream os = new FileOutputStream(this.mCurProfile);
                    Encoding.writeAll(bis, os);
                    result(1, null);
                    os.close();
                    bis.close();
                    return true;
                } catch (Throwable th) {
                    try {
                        bis.close();
                    } catch (Throwable th2) {
                        th.addSuppressed(th2);
                    }
                    throw th;
                }
            } catch (FileNotFoundException e) {
                result(6, e);
                return false;
            } catch (IOException e2) {
                result(7, e2);
                return false;
            }
        } finally {
            this.mTranscodedProfile = null;
            this.mProfile = null;
        }
    }

    private static byte[] desiredVersion() {
        if (Build.VERSION.SDK_INT > 33) {
            return null;
        }
        switch (Build.VERSION.SDK_INT) {
            case 24:
            case 25:
                return ProfileVersion.V001_N;
            case 26:
                return ProfileVersion.V005_O;
            case 27:
                return ProfileVersion.V009_O_MR1;
            case 28:
            case ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_HORIZONTAL_BIAS /* 29 */:
            case 30:
                return ProfileVersion.V010_P;
            case ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_WIDTH_DEFAULT /* 31 */:
            case 32:
            case 33:
                return ProfileVersion.V015_S;
            default:
                return null;
        }
    }

    private static boolean requiresMetadata() {
        if (Build.VERSION.SDK_INT > 33) {
            return false;
        }
        switch (Build.VERSION.SDK_INT) {
            case 24:
            case 25:
                return true;
            case 26:
            case 27:
            case 28:
            case ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_HORIZONTAL_BIAS /* 29 */:
            case 30:
                return false;
            case ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_WIDTH_DEFAULT /* 31 */:
            case 32:
            case 33:
                return true;
            default:
                return false;
        }
    }
}
