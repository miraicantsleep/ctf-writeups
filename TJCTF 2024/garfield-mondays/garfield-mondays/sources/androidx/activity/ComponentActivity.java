package androidx.activity;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.content.res.Configuration;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.text.TextUtils;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.view.Window;
import android.window.OnBackInvokedDispatcher;
import androidx.activity.ComponentActivity;
import androidx.activity.contextaware.ContextAware;
import androidx.activity.contextaware.ContextAwareHelper;
import androidx.activity.contextaware.OnContextAvailableListener;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultCaller;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.ActivityResultRegistry;
import androidx.activity.result.ActivityResultRegistryOwner;
import androidx.activity.result.IntentSenderRequest;
import androidx.activity.result.contract.ActivityResultContract;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.core.app.ActivityCompat;
import androidx.core.app.ActivityOptionsCompat;
import androidx.core.app.MultiWindowModeChangedInfo;
import androidx.core.app.OnMultiWindowModeChangedProvider;
import androidx.core.app.OnNewIntentProvider;
import androidx.core.app.OnPictureInPictureModeChangedProvider;
import androidx.core.app.PictureInPictureModeChangedInfo;
import androidx.core.content.OnConfigurationChangedProvider;
import androidx.core.content.OnTrimMemoryProvider;
import androidx.core.util.Consumer;
import androidx.core.view.MenuHost;
import androidx.core.view.MenuHostHelper;
import androidx.core.view.MenuProvider;
import androidx.lifecycle.HasDefaultViewModelProviderFactory;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.LifecycleEventObserver;
import androidx.lifecycle.LifecycleOwner;
import androidx.lifecycle.LifecycleRegistry;
import androidx.lifecycle.ReportFragment;
import androidx.lifecycle.SavedStateHandleSupport;
import androidx.lifecycle.SavedStateViewModelFactory;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import androidx.lifecycle.ViewTreeLifecycleOwner;
import androidx.lifecycle.ViewTreeViewModelStoreOwner;
import androidx.lifecycle.viewmodel.CreationExtras;
import androidx.lifecycle.viewmodel.MutableCreationExtras;
import androidx.savedstate.SavedStateRegistry;
import androidx.savedstate.SavedStateRegistryController;
import androidx.savedstate.SavedStateRegistryOwner;
import androidx.savedstate.ViewTreeSavedStateRegistryOwner;
import androidx.tracing.Trace;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
/* loaded from: classes.dex */
public class ComponentActivity extends androidx.core.app.ComponentActivity implements ContextAware, LifecycleOwner, ViewModelStoreOwner, HasDefaultViewModelProviderFactory, SavedStateRegistryOwner, OnBackPressedDispatcherOwner, ActivityResultRegistryOwner, ActivityResultCaller, OnConfigurationChangedProvider, OnTrimMemoryProvider, OnNewIntentProvider, OnMultiWindowModeChangedProvider, OnPictureInPictureModeChangedProvider, MenuHost, FullyDrawnReporterOwner {
    private static final String ACTIVITY_RESULT_TAG = "android:support:activity-result";
    private final ActivityResultRegistry mActivityResultRegistry;
    private int mContentLayoutId;
    final ContextAwareHelper mContextAwareHelper;
    private ViewModelProvider.Factory mDefaultFactory;
    private boolean mDispatchingOnMultiWindowModeChanged;
    private boolean mDispatchingOnPictureInPictureModeChanged;
    final FullyDrawnReporter mFullyDrawnReporter;
    private final LifecycleRegistry mLifecycleRegistry;
    private final MenuHostHelper mMenuHostHelper;
    private final AtomicInteger mNextLocalRequestCode;
    private OnBackPressedDispatcher mOnBackPressedDispatcher;
    private final CopyOnWriteArrayList<Consumer<Configuration>> mOnConfigurationChangedListeners;
    private final CopyOnWriteArrayList<Consumer<MultiWindowModeChangedInfo>> mOnMultiWindowModeChangedListeners;
    private final CopyOnWriteArrayList<Consumer<Intent>> mOnNewIntentListeners;
    private final CopyOnWriteArrayList<Consumer<PictureInPictureModeChangedInfo>> mOnPictureInPictureModeChangedListeners;
    private final CopyOnWriteArrayList<Consumer<Integer>> mOnTrimMemoryListeners;
    final ReportFullyDrawnExecutor mReportFullyDrawnExecutor;
    final SavedStateRegistryController mSavedStateRegistryController;
    private ViewModelStore mViewModelStore;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public interface ReportFullyDrawnExecutor extends Executor {
        void activityDestroyed();

        void viewCreated(View view);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class NonConfigurationInstances {
        Object custom;
        ViewModelStore viewModelStore;

        NonConfigurationInstances() {
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$new$0$androidx-activity-ComponentActivity  reason: not valid java name */
    public /* synthetic */ Unit m0lambda$new$0$androidxactivityComponentActivity() {
        reportFullyDrawn();
        return null;
    }

    public ComponentActivity() {
        this.mContextAwareHelper = new ContextAwareHelper();
        this.mMenuHostHelper = new MenuHostHelper(new Runnable() { // from class: androidx.activity.ComponentActivity$$ExternalSyntheticLambda0
            @Override // java.lang.Runnable
            public final void run() {
                ComponentActivity.this.invalidateMenu();
            }
        });
        this.mLifecycleRegistry = new LifecycleRegistry(this);
        this.mSavedStateRegistryController = SavedStateRegistryController.create(this);
        this.mOnBackPressedDispatcher = null;
        this.mReportFullyDrawnExecutor = createFullyDrawnExecutor();
        this.mFullyDrawnReporter = new FullyDrawnReporter(this.mReportFullyDrawnExecutor, new Function0() { // from class: androidx.activity.ComponentActivity$$ExternalSyntheticLambda1
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                return ComponentActivity.this.m0lambda$new$0$androidxactivityComponentActivity();
            }
        });
        this.mNextLocalRequestCode = new AtomicInteger();
        this.mActivityResultRegistry = new ActivityResultRegistry() { // from class: androidx.activity.ComponentActivity.1
            @Override // androidx.activity.result.ActivityResultRegistry
            public <I, O> void onLaunch(final int requestCode, ActivityResultContract<I, O> contract, I input, ActivityOptionsCompat options) {
                Bundle optionsBundle;
                Bundle optionsBundle2;
                ComponentActivity activity = ComponentActivity.this;
                final ActivityResultContract.SynchronousResult<O> synchronousResult = contract.getSynchronousResult(activity, input);
                if (synchronousResult != null) {
                    new Handler(Looper.getMainLooper()).post(new Runnable() { // from class: androidx.activity.ComponentActivity.1.1
                        @Override // java.lang.Runnable
                        public void run() {
                            dispatchResult(requestCode, synchronousResult.getValue());
                        }
                    });
                    return;
                }
                Intent intent = contract.createIntent(activity, input);
                if (intent.getExtras() != null && intent.getExtras().getClassLoader() == null) {
                    intent.setExtrasClassLoader(activity.getClassLoader());
                }
                if (intent.hasExtra(ActivityResultContracts.StartActivityForResult.EXTRA_ACTIVITY_OPTIONS_BUNDLE)) {
                    Bundle optionsBundle3 = intent.getBundleExtra(ActivityResultContracts.StartActivityForResult.EXTRA_ACTIVITY_OPTIONS_BUNDLE);
                    intent.removeExtra(ActivityResultContracts.StartActivityForResult.EXTRA_ACTIVITY_OPTIONS_BUNDLE);
                    optionsBundle = optionsBundle3;
                } else if (options == null) {
                    optionsBundle = null;
                } else {
                    Bundle optionsBundle4 = options.toBundle();
                    optionsBundle = optionsBundle4;
                }
                if (ActivityResultContracts.RequestMultiplePermissions.ACTION_REQUEST_PERMISSIONS.equals(intent.getAction())) {
                    String[] permissions = intent.getStringArrayExtra(ActivityResultContracts.RequestMultiplePermissions.EXTRA_PERMISSIONS);
                    if (permissions == null) {
                        permissions = new String[0];
                    }
                    ActivityCompat.requestPermissions(activity, permissions, requestCode);
                } else if (ActivityResultContracts.StartIntentSenderForResult.ACTION_INTENT_SENDER_REQUEST.equals(intent.getAction())) {
                    IntentSenderRequest request = (IntentSenderRequest) intent.getParcelableExtra(ActivityResultContracts.StartIntentSenderForResult.EXTRA_INTENT_SENDER_REQUEST);
                    try {
                        optionsBundle2 = optionsBundle;
                        try {
                            ActivityCompat.startIntentSenderForResult(activity, request.getIntentSender(), requestCode, request.getFillInIntent(), request.getFlagsMask(), request.getFlagsValues(), 0, optionsBundle2);
                        } catch (IntentSender.SendIntentException e) {
                            e = e;
                            new Handler(Looper.getMainLooper()).post(new Runnable() { // from class: androidx.activity.ComponentActivity.1.2
                                @Override // java.lang.Runnable
                                public void run() {
                                    dispatchResult(requestCode, 0, new Intent().setAction(ActivityResultContracts.StartIntentSenderForResult.ACTION_INTENT_SENDER_REQUEST).putExtra(ActivityResultContracts.StartIntentSenderForResult.EXTRA_SEND_INTENT_EXCEPTION, e));
                                }
                            });
                        }
                    } catch (IntentSender.SendIntentException e2) {
                        e = e2;
                        optionsBundle2 = optionsBundle;
                    }
                } else {
                    ActivityCompat.startActivityForResult(activity, intent, requestCode, optionsBundle);
                }
            }
        };
        this.mOnConfigurationChangedListeners = new CopyOnWriteArrayList<>();
        this.mOnTrimMemoryListeners = new CopyOnWriteArrayList<>();
        this.mOnNewIntentListeners = new CopyOnWriteArrayList<>();
        this.mOnMultiWindowModeChangedListeners = new CopyOnWriteArrayList<>();
        this.mOnPictureInPictureModeChangedListeners = new CopyOnWriteArrayList<>();
        this.mDispatchingOnMultiWindowModeChanged = false;
        this.mDispatchingOnPictureInPictureModeChanged = false;
        Lifecycle lifecycle = getLifecycle();
        if (lifecycle == null) {
            throw new IllegalStateException("getLifecycle() returned null in ComponentActivity's constructor. Please make sure you are lazily constructing your Lifecycle in the first call to getLifecycle() rather than relying on field initialization.");
        }
        getLifecycle().addObserver(new LifecycleEventObserver() { // from class: androidx.activity.ComponentActivity.2
            @Override // androidx.lifecycle.LifecycleEventObserver
            public void onStateChanged(LifecycleOwner source, Lifecycle.Event event) {
                if (event == Lifecycle.Event.ON_STOP) {
                    Window window = ComponentActivity.this.getWindow();
                    View decor = window != null ? window.peekDecorView() : null;
                    if (decor != null) {
                        Api19Impl.cancelPendingInputEvents(decor);
                    }
                }
            }
        });
        getLifecycle().addObserver(new LifecycleEventObserver() { // from class: androidx.activity.ComponentActivity.3
            @Override // androidx.lifecycle.LifecycleEventObserver
            public void onStateChanged(LifecycleOwner source, Lifecycle.Event event) {
                if (event == Lifecycle.Event.ON_DESTROY) {
                    ComponentActivity.this.mContextAwareHelper.clearAvailableContext();
                    if (!ComponentActivity.this.isChangingConfigurations()) {
                        ComponentActivity.this.getViewModelStore().clear();
                    }
                    ComponentActivity.this.mReportFullyDrawnExecutor.activityDestroyed();
                }
            }
        });
        getLifecycle().addObserver(new LifecycleEventObserver() { // from class: androidx.activity.ComponentActivity.4
            @Override // androidx.lifecycle.LifecycleEventObserver
            public void onStateChanged(LifecycleOwner source, Lifecycle.Event event) {
                ComponentActivity.this.ensureViewModelStore();
                ComponentActivity.this.getLifecycle().removeObserver(this);
            }
        });
        this.mSavedStateRegistryController.performAttach();
        SavedStateHandleSupport.enableSavedStateHandles(this);
        getSavedStateRegistry().registerSavedStateProvider(ACTIVITY_RESULT_TAG, new SavedStateRegistry.SavedStateProvider() { // from class: androidx.activity.ComponentActivity$$ExternalSyntheticLambda2
            @Override // androidx.savedstate.SavedStateRegistry.SavedStateProvider
            public final Bundle saveState() {
                return ComponentActivity.this.m1lambda$new$1$androidxactivityComponentActivity();
            }
        });
        addOnContextAvailableListener(new OnContextAvailableListener() { // from class: androidx.activity.ComponentActivity$$ExternalSyntheticLambda3
            @Override // androidx.activity.contextaware.OnContextAvailableListener
            public final void onContextAvailable(Context context) {
                ComponentActivity.this.m2lambda$new$2$androidxactivityComponentActivity(context);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$new$1$androidx-activity-ComponentActivity  reason: not valid java name */
    public /* synthetic */ Bundle m1lambda$new$1$androidxactivityComponentActivity() {
        Bundle outState = new Bundle();
        this.mActivityResultRegistry.onSaveInstanceState(outState);
        return outState;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: lambda$new$2$androidx-activity-ComponentActivity  reason: not valid java name */
    public /* synthetic */ void m2lambda$new$2$androidxactivityComponentActivity(Context context) {
        Bundle savedInstanceState = getSavedStateRegistry().consumeRestoredStateForKey(ACTIVITY_RESULT_TAG);
        if (savedInstanceState != null) {
            this.mActivityResultRegistry.onRestoreInstanceState(savedInstanceState);
        }
    }

    public ComponentActivity(int contentLayoutId) {
        this();
        this.mContentLayoutId = contentLayoutId;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        this.mSavedStateRegistryController.performRestore(savedInstanceState);
        this.mContextAwareHelper.dispatchOnContextAvailable(this);
        super.onCreate(savedInstanceState);
        ReportFragment.injectIfNeededIn(this);
        if (this.mContentLayoutId != 0) {
            setContentView(this.mContentLayoutId);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.core.app.ComponentActivity, android.app.Activity
    public void onSaveInstanceState(Bundle outState) {
        Lifecycle lifecycle = getLifecycle();
        if (lifecycle instanceof LifecycleRegistry) {
            ((LifecycleRegistry) lifecycle).setCurrentState(Lifecycle.State.CREATED);
        }
        super.onSaveInstanceState(outState);
        this.mSavedStateRegistryController.performSave(outState);
    }

    @Override // android.app.Activity
    public final Object onRetainNonConfigurationInstance() {
        NonConfigurationInstances nc;
        Object custom = onRetainCustomNonConfigurationInstance();
        ViewModelStore viewModelStore = this.mViewModelStore;
        if (viewModelStore == null && (nc = (NonConfigurationInstances) getLastNonConfigurationInstance()) != null) {
            viewModelStore = nc.viewModelStore;
        }
        if (viewModelStore == null && custom == null) {
            return null;
        }
        NonConfigurationInstances nci = new NonConfigurationInstances();
        nci.custom = custom;
        nci.viewModelStore = viewModelStore;
        return nci;
    }

    @Deprecated
    public Object onRetainCustomNonConfigurationInstance() {
        return null;
    }

    @Deprecated
    public Object getLastCustomNonConfigurationInstance() {
        NonConfigurationInstances nc = (NonConfigurationInstances) getLastNonConfigurationInstance();
        if (nc != null) {
            return nc.custom;
        }
        return null;
    }

    @Override // android.app.Activity
    public void setContentView(int layoutResID) {
        initializeViewTreeOwners();
        this.mReportFullyDrawnExecutor.viewCreated(getWindow().getDecorView());
        super.setContentView(layoutResID);
    }

    @Override // android.app.Activity
    public void setContentView(View view) {
        initializeViewTreeOwners();
        this.mReportFullyDrawnExecutor.viewCreated(getWindow().getDecorView());
        super.setContentView(view);
    }

    @Override // android.app.Activity
    public void setContentView(View view, ViewGroup.LayoutParams params) {
        initializeViewTreeOwners();
        this.mReportFullyDrawnExecutor.viewCreated(getWindow().getDecorView());
        super.setContentView(view, params);
    }

    @Override // android.app.Activity
    public void addContentView(View view, ViewGroup.LayoutParams params) {
        initializeViewTreeOwners();
        this.mReportFullyDrawnExecutor.viewCreated(getWindow().getDecorView());
        super.addContentView(view, params);
    }

    public void initializeViewTreeOwners() {
        ViewTreeLifecycleOwner.set(getWindow().getDecorView(), this);
        ViewTreeViewModelStoreOwner.set(getWindow().getDecorView(), this);
        ViewTreeSavedStateRegistryOwner.set(getWindow().getDecorView(), this);
        ViewTreeOnBackPressedDispatcherOwner.set(getWindow().getDecorView(), this);
        ViewTreeFullyDrawnReporterOwner.set(getWindow().getDecorView(), this);
    }

    @Override // androidx.activity.contextaware.ContextAware
    public Context peekAvailableContext() {
        return this.mContextAwareHelper.peekAvailableContext();
    }

    @Override // androidx.activity.contextaware.ContextAware
    public final void addOnContextAvailableListener(OnContextAvailableListener listener) {
        this.mContextAwareHelper.addOnContextAvailableListener(listener);
    }

    @Override // androidx.activity.contextaware.ContextAware
    public final void removeOnContextAvailableListener(OnContextAvailableListener listener) {
        this.mContextAwareHelper.removeOnContextAvailableListener(listener);
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public boolean onPreparePanel(int featureId, View view, Menu menu) {
        if (featureId == 0) {
            super.onPreparePanel(featureId, view, menu);
            this.mMenuHostHelper.onPrepareMenu(menu);
            return true;
        }
        return true;
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public boolean onCreatePanelMenu(int featureId, Menu menu) {
        if (featureId == 0) {
            super.onCreatePanelMenu(featureId, menu);
            this.mMenuHostHelper.onCreateMenu(menu, getMenuInflater());
            return true;
        }
        return true;
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public boolean onMenuItemSelected(int featureId, MenuItem item) {
        if (super.onMenuItemSelected(featureId, item)) {
            return true;
        }
        if (featureId == 0) {
            return this.mMenuHostHelper.onMenuItemSelected(item);
        }
        return false;
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public void onPanelClosed(int featureId, Menu menu) {
        this.mMenuHostHelper.onMenuClosed(menu);
        super.onPanelClosed(featureId, menu);
    }

    @Override // androidx.core.view.MenuHost
    public void addMenuProvider(MenuProvider provider) {
        this.mMenuHostHelper.addMenuProvider(provider);
    }

    @Override // androidx.core.view.MenuHost
    public void addMenuProvider(MenuProvider provider, LifecycleOwner owner) {
        this.mMenuHostHelper.addMenuProvider(provider, owner);
    }

    @Override // androidx.core.view.MenuHost
    public void addMenuProvider(MenuProvider provider, LifecycleOwner owner, Lifecycle.State state) {
        this.mMenuHostHelper.addMenuProvider(provider, owner, state);
    }

    @Override // androidx.core.view.MenuHost
    public void removeMenuProvider(MenuProvider provider) {
        this.mMenuHostHelper.removeMenuProvider(provider);
    }

    @Override // androidx.core.view.MenuHost
    public void invalidateMenu() {
        invalidateOptionsMenu();
    }

    @Override // androidx.core.app.ComponentActivity, androidx.lifecycle.LifecycleOwner
    public Lifecycle getLifecycle() {
        return this.mLifecycleRegistry;
    }

    @Override // androidx.lifecycle.ViewModelStoreOwner
    public ViewModelStore getViewModelStore() {
        if (getApplication() == null) {
            throw new IllegalStateException("Your activity is not yet attached to the Application instance. You can't request ViewModel before onCreate call.");
        }
        ensureViewModelStore();
        return this.mViewModelStore;
    }

    void ensureViewModelStore() {
        if (this.mViewModelStore == null) {
            NonConfigurationInstances nc = (NonConfigurationInstances) getLastNonConfigurationInstance();
            if (nc != null) {
                this.mViewModelStore = nc.viewModelStore;
            }
            if (this.mViewModelStore == null) {
                this.mViewModelStore = new ViewModelStore();
            }
        }
    }

    @Override // androidx.lifecycle.HasDefaultViewModelProviderFactory
    public ViewModelProvider.Factory getDefaultViewModelProviderFactory() {
        if (this.mDefaultFactory == null) {
            this.mDefaultFactory = new SavedStateViewModelFactory(getApplication(), this, getIntent() != null ? getIntent().getExtras() : null);
        }
        return this.mDefaultFactory;
    }

    @Override // androidx.lifecycle.HasDefaultViewModelProviderFactory
    public CreationExtras getDefaultViewModelCreationExtras() {
        MutableCreationExtras extras = new MutableCreationExtras();
        if (getApplication() != null) {
            extras.set(ViewModelProvider.AndroidViewModelFactory.APPLICATION_KEY, getApplication());
        }
        extras.set(SavedStateHandleSupport.SAVED_STATE_REGISTRY_OWNER_KEY, this);
        extras.set(SavedStateHandleSupport.VIEW_MODEL_STORE_OWNER_KEY, this);
        if (getIntent() != null && getIntent().getExtras() != null) {
            extras.set(SavedStateHandleSupport.DEFAULT_ARGS_KEY, getIntent().getExtras());
        }
        return extras;
    }

    @Override // android.app.Activity
    @Deprecated
    public void onBackPressed() {
        getOnBackPressedDispatcher().onBackPressed();
    }

    @Override // androidx.activity.OnBackPressedDispatcherOwner
    public final OnBackPressedDispatcher getOnBackPressedDispatcher() {
        if (this.mOnBackPressedDispatcher == null) {
            this.mOnBackPressedDispatcher = new OnBackPressedDispatcher(new Runnable() { // from class: androidx.activity.ComponentActivity.5
                @Override // java.lang.Runnable
                public void run() {
                    try {
                        ComponentActivity.super.onBackPressed();
                    } catch (IllegalStateException e) {
                        if (!TextUtils.equals(e.getMessage(), "Can not perform this action after onSaveInstanceState")) {
                            throw e;
                        }
                    } catch (NullPointerException e2) {
                        if (!TextUtils.equals(e2.getMessage(), "Attempt to invoke virtual method 'android.os.Handler android.app.FragmentHostCallback.getHandler()' on a null object reference")) {
                            throw e2;
                        }
                    }
                }
            });
            getLifecycle().addObserver(new LifecycleEventObserver() { // from class: androidx.activity.ComponentActivity.6
                @Override // androidx.lifecycle.LifecycleEventObserver
                public void onStateChanged(LifecycleOwner lifecycleOwner, Lifecycle.Event event) {
                    if (event == Lifecycle.Event.ON_CREATE && Build.VERSION.SDK_INT >= 33) {
                        ComponentActivity.this.mOnBackPressedDispatcher.setOnBackInvokedDispatcher(Api33Impl.getOnBackInvokedDispatcher((ComponentActivity) lifecycleOwner));
                    }
                }
            });
        }
        return this.mOnBackPressedDispatcher;
    }

    @Override // androidx.savedstate.SavedStateRegistryOwner
    public final SavedStateRegistry getSavedStateRegistry() {
        return this.mSavedStateRegistryController.getSavedStateRegistry();
    }

    @Override // androidx.activity.FullyDrawnReporterOwner
    public FullyDrawnReporter getFullyDrawnReporter() {
        return this.mFullyDrawnReporter;
    }

    @Override // android.app.Activity
    @Deprecated
    public void startActivityForResult(Intent intent, int requestCode) {
        super.startActivityForResult(intent, requestCode);
    }

    @Override // android.app.Activity
    @Deprecated
    public void startActivityForResult(Intent intent, int requestCode, Bundle options) {
        super.startActivityForResult(intent, requestCode, options);
    }

    @Override // android.app.Activity
    @Deprecated
    public void startIntentSenderForResult(IntentSender intent, int requestCode, Intent fillInIntent, int flagsMask, int flagsValues, int extraFlags) throws IntentSender.SendIntentException {
        super.startIntentSenderForResult(intent, requestCode, fillInIntent, flagsMask, flagsValues, extraFlags);
    }

    @Override // android.app.Activity
    @Deprecated
    public void startIntentSenderForResult(IntentSender intent, int requestCode, Intent fillInIntent, int flagsMask, int flagsValues, int extraFlags, Bundle options) throws IntentSender.SendIntentException {
        super.startIntentSenderForResult(intent, requestCode, fillInIntent, flagsMask, flagsValues, extraFlags, options);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // android.app.Activity
    @Deprecated
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (!this.mActivityResultRegistry.dispatchResult(requestCode, resultCode, data)) {
            super.onActivityResult(requestCode, resultCode, data);
        }
    }

    @Override // android.app.Activity
    @Deprecated
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        if (!this.mActivityResultRegistry.dispatchResult(requestCode, -1, new Intent().putExtra(ActivityResultContracts.RequestMultiplePermissions.EXTRA_PERMISSIONS, permissions).putExtra(ActivityResultContracts.RequestMultiplePermissions.EXTRA_PERMISSION_GRANT_RESULTS, grantResults))) {
            super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        }
    }

    @Override // androidx.activity.result.ActivityResultCaller
    public final <I, O> ActivityResultLauncher<I> registerForActivityResult(ActivityResultContract<I, O> contract, ActivityResultRegistry registry, ActivityResultCallback<O> callback) {
        return registry.register("activity_rq#" + this.mNextLocalRequestCode.getAndIncrement(), this, contract, callback);
    }

    @Override // androidx.activity.result.ActivityResultCaller
    public final <I, O> ActivityResultLauncher<I> registerForActivityResult(ActivityResultContract<I, O> contract, ActivityResultCallback<O> callback) {
        return registerForActivityResult(contract, this.mActivityResultRegistry, callback);
    }

    @Override // androidx.activity.result.ActivityResultRegistryOwner
    public final ActivityResultRegistry getActivityResultRegistry() {
        return this.mActivityResultRegistry;
    }

    @Override // android.app.Activity, android.content.ComponentCallbacks
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        Iterator<Consumer<Configuration>> it = this.mOnConfigurationChangedListeners.iterator();
        while (it.hasNext()) {
            Consumer<Configuration> listener = it.next();
            listener.accept(newConfig);
        }
    }

    @Override // androidx.core.content.OnConfigurationChangedProvider
    public final void addOnConfigurationChangedListener(Consumer<Configuration> listener) {
        this.mOnConfigurationChangedListeners.add(listener);
    }

    @Override // androidx.core.content.OnConfigurationChangedProvider
    public final void removeOnConfigurationChangedListener(Consumer<Configuration> listener) {
        this.mOnConfigurationChangedListeners.remove(listener);
    }

    @Override // android.app.Activity, android.content.ComponentCallbacks2
    public void onTrimMemory(int level) {
        super.onTrimMemory(level);
        Iterator<Consumer<Integer>> it = this.mOnTrimMemoryListeners.iterator();
        while (it.hasNext()) {
            Consumer<Integer> listener = it.next();
            listener.accept(Integer.valueOf(level));
        }
    }

    @Override // androidx.core.content.OnTrimMemoryProvider
    public final void addOnTrimMemoryListener(Consumer<Integer> listener) {
        this.mOnTrimMemoryListeners.add(listener);
    }

    @Override // androidx.core.content.OnTrimMemoryProvider
    public final void removeOnTrimMemoryListener(Consumer<Integer> listener) {
        this.mOnTrimMemoryListeners.remove(listener);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // android.app.Activity
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        Iterator<Consumer<Intent>> it = this.mOnNewIntentListeners.iterator();
        while (it.hasNext()) {
            Consumer<Intent> listener = it.next();
            listener.accept(intent);
        }
    }

    @Override // androidx.core.app.OnNewIntentProvider
    public final void addOnNewIntentListener(Consumer<Intent> listener) {
        this.mOnNewIntentListeners.add(listener);
    }

    @Override // androidx.core.app.OnNewIntentProvider
    public final void removeOnNewIntentListener(Consumer<Intent> listener) {
        this.mOnNewIntentListeners.remove(listener);
    }

    @Override // android.app.Activity
    public void onMultiWindowModeChanged(boolean isInMultiWindowMode) {
        if (this.mDispatchingOnMultiWindowModeChanged) {
            return;
        }
        Iterator<Consumer<MultiWindowModeChangedInfo>> it = this.mOnMultiWindowModeChangedListeners.iterator();
        while (it.hasNext()) {
            Consumer<MultiWindowModeChangedInfo> listener = it.next();
            listener.accept(new MultiWindowModeChangedInfo(isInMultiWindowMode));
        }
    }

    @Override // android.app.Activity
    public void onMultiWindowModeChanged(boolean isInMultiWindowMode, Configuration newConfig) {
        this.mDispatchingOnMultiWindowModeChanged = true;
        try {
            super.onMultiWindowModeChanged(isInMultiWindowMode, newConfig);
            this.mDispatchingOnMultiWindowModeChanged = false;
            Iterator<Consumer<MultiWindowModeChangedInfo>> it = this.mOnMultiWindowModeChangedListeners.iterator();
            while (it.hasNext()) {
                Consumer<MultiWindowModeChangedInfo> listener = it.next();
                listener.accept(new MultiWindowModeChangedInfo(isInMultiWindowMode, newConfig));
            }
        } catch (Throwable th) {
            this.mDispatchingOnMultiWindowModeChanged = false;
            throw th;
        }
    }

    @Override // androidx.core.app.OnMultiWindowModeChangedProvider
    public final void addOnMultiWindowModeChangedListener(Consumer<MultiWindowModeChangedInfo> listener) {
        this.mOnMultiWindowModeChangedListeners.add(listener);
    }

    @Override // androidx.core.app.OnMultiWindowModeChangedProvider
    public final void removeOnMultiWindowModeChangedListener(Consumer<MultiWindowModeChangedInfo> listener) {
        this.mOnMultiWindowModeChangedListeners.remove(listener);
    }

    @Override // android.app.Activity
    public void onPictureInPictureModeChanged(boolean isInPictureInPictureMode) {
        if (this.mDispatchingOnPictureInPictureModeChanged) {
            return;
        }
        Iterator<Consumer<PictureInPictureModeChangedInfo>> it = this.mOnPictureInPictureModeChangedListeners.iterator();
        while (it.hasNext()) {
            Consumer<PictureInPictureModeChangedInfo> listener = it.next();
            listener.accept(new PictureInPictureModeChangedInfo(isInPictureInPictureMode));
        }
    }

    @Override // android.app.Activity
    public void onPictureInPictureModeChanged(boolean isInPictureInPictureMode, Configuration newConfig) {
        this.mDispatchingOnPictureInPictureModeChanged = true;
        try {
            super.onPictureInPictureModeChanged(isInPictureInPictureMode, newConfig);
            this.mDispatchingOnPictureInPictureModeChanged = false;
            Iterator<Consumer<PictureInPictureModeChangedInfo>> it = this.mOnPictureInPictureModeChangedListeners.iterator();
            while (it.hasNext()) {
                Consumer<PictureInPictureModeChangedInfo> listener = it.next();
                listener.accept(new PictureInPictureModeChangedInfo(isInPictureInPictureMode, newConfig));
            }
        } catch (Throwable th) {
            this.mDispatchingOnPictureInPictureModeChanged = false;
            throw th;
        }
    }

    @Override // androidx.core.app.OnPictureInPictureModeChangedProvider
    public final void addOnPictureInPictureModeChangedListener(Consumer<PictureInPictureModeChangedInfo> listener) {
        this.mOnPictureInPictureModeChangedListeners.add(listener);
    }

    @Override // androidx.core.app.OnPictureInPictureModeChangedProvider
    public final void removeOnPictureInPictureModeChangedListener(Consumer<PictureInPictureModeChangedInfo> listener) {
        this.mOnPictureInPictureModeChangedListeners.remove(listener);
    }

    @Override // android.app.Activity
    public void reportFullyDrawn() {
        try {
            if (Trace.isEnabled()) {
                Trace.beginSection("reportFullyDrawn() for ComponentActivity");
            }
            super.reportFullyDrawn();
            this.mFullyDrawnReporter.fullyDrawnReported();
        } finally {
            Trace.endSection();
        }
    }

    private ReportFullyDrawnExecutor createFullyDrawnExecutor() {
        return new ReportFullyDrawnExecutorApi16Impl();
    }

    /* loaded from: classes.dex */
    static class Api19Impl {
        private Api19Impl() {
        }

        static void cancelPendingInputEvents(View view) {
            view.cancelPendingInputEvents();
        }
    }

    /* loaded from: classes.dex */
    static class Api33Impl {
        private Api33Impl() {
        }

        static OnBackInvokedDispatcher getOnBackInvokedDispatcher(Activity activity) {
            return activity.getOnBackInvokedDispatcher();
        }
    }

    /* loaded from: classes.dex */
    static class ReportFullyDrawnExecutorApi1 implements ReportFullyDrawnExecutor {
        final Handler mHandler = createHandler();

        ReportFullyDrawnExecutorApi1() {
        }

        @Override // androidx.activity.ComponentActivity.ReportFullyDrawnExecutor
        public void viewCreated(View view) {
        }

        @Override // androidx.activity.ComponentActivity.ReportFullyDrawnExecutor
        public void activityDestroyed() {
        }

        @Override // java.util.concurrent.Executor
        public void execute(Runnable runnable) {
            this.mHandler.postAtFrontOfQueue(runnable);
        }

        private Handler createHandler() {
            Looper looper = Looper.myLooper();
            return new Handler(looper == null ? Looper.getMainLooper() : looper);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class ReportFullyDrawnExecutorApi16Impl implements ReportFullyDrawnExecutor, ViewTreeObserver.OnDrawListener, Runnable {
        final long mEndWatchTimeMillis = SystemClock.uptimeMillis() + 10000;
        boolean mOnDrawScheduled = false;
        Runnable mRunnable;

        ReportFullyDrawnExecutorApi16Impl() {
        }

        @Override // androidx.activity.ComponentActivity.ReportFullyDrawnExecutor
        public void viewCreated(View view) {
            if (!this.mOnDrawScheduled) {
                this.mOnDrawScheduled = true;
                view.getViewTreeObserver().addOnDrawListener(this);
            }
        }

        @Override // androidx.activity.ComponentActivity.ReportFullyDrawnExecutor
        public void activityDestroyed() {
            ComponentActivity.this.getWindow().getDecorView().removeCallbacks(this);
            ComponentActivity.this.getWindow().getDecorView().getViewTreeObserver().removeOnDrawListener(this);
        }

        @Override // java.util.concurrent.Executor
        public void execute(Runnable runnable) {
            this.mRunnable = runnable;
            View decorView = ComponentActivity.this.getWindow().getDecorView();
            if (this.mOnDrawScheduled) {
                if (Looper.myLooper() == Looper.getMainLooper()) {
                    decorView.invalidate();
                    return;
                } else {
                    decorView.postInvalidate();
                    return;
                }
            }
            decorView.postOnAnimation(new Runnable() { // from class: androidx.activity.ComponentActivity$ReportFullyDrawnExecutorApi16Impl$$ExternalSyntheticLambda0
                @Override // java.lang.Runnable
                public final void run() {
                    ComponentActivity.ReportFullyDrawnExecutorApi16Impl.this.m3x96b76666();
                }
            });
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        /* renamed from: lambda$execute$0$androidx-activity-ComponentActivity$ReportFullyDrawnExecutorApi16Impl  reason: not valid java name */
        public /* synthetic */ void m3x96b76666() {
            if (this.mRunnable != null) {
                this.mRunnable.run();
                this.mRunnable = null;
            }
        }

        @Override // android.view.ViewTreeObserver.OnDrawListener
        public void onDraw() {
            Runnable runnable = this.mRunnable;
            if (runnable != null) {
                runnable.run();
                this.mRunnable = null;
                if (ComponentActivity.this.mFullyDrawnReporter.isFullyDrawnReported()) {
                    this.mOnDrawScheduled = false;
                    ComponentActivity.this.getWindow().getDecorView().post(this);
                }
            } else if (SystemClock.uptimeMillis() > this.mEndWatchTimeMillis) {
                this.mOnDrawScheduled = false;
                ComponentActivity.this.getWindow().getDecorView().post(this);
            }
        }

        @Override // java.lang.Runnable
        public void run() {
            ComponentActivity.this.getWindow().getDecorView().getViewTreeObserver().removeOnDrawListener(this);
        }
    }
}
