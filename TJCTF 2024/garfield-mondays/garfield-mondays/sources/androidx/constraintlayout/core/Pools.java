package androidx.constraintlayout.core;
/* loaded from: classes.dex */
final class Pools {
    private static final boolean DEBUG = false;

    /* loaded from: classes.dex */
    interface Pool<T> {
        T acquire();

        boolean release(T t);

        void releaseAll(T[] tArr, int i);
    }

    private Pools() {
    }

    /* loaded from: classes.dex */
    static class SimplePool<T> implements Pool<T> {
        private final Object[] mPool;
        private int mPoolSize;

        /* JADX INFO: Access modifiers changed from: package-private */
        public SimplePool(int maxPoolSize) {
            if (maxPoolSize <= 0) {
                throw new IllegalArgumentException("The max pool size must be > 0");
            }
            this.mPool = new Object[maxPoolSize];
        }

        @Override // androidx.constraintlayout.core.Pools.Pool
        public T acquire() {
            if (this.mPoolSize > 0) {
                int lastPooledIndex = this.mPoolSize - 1;
                T instance = (T) this.mPool[lastPooledIndex];
                this.mPool[lastPooledIndex] = null;
                this.mPoolSize--;
                return instance;
            }
            return null;
        }

        @Override // androidx.constraintlayout.core.Pools.Pool
        public boolean release(T instance) {
            if (this.mPoolSize < this.mPool.length) {
                this.mPool[this.mPoolSize] = instance;
                this.mPoolSize++;
                return true;
            }
            return false;
        }

        @Override // androidx.constraintlayout.core.Pools.Pool
        public void releaseAll(T[] variables, int count) {
            if (count > variables.length) {
                count = variables.length;
            }
            for (int i = 0; i < count; i++) {
                T instance = variables[i];
                if (this.mPoolSize < this.mPool.length) {
                    this.mPool[this.mPoolSize] = instance;
                    this.mPoolSize++;
                }
            }
        }

        private boolean isInPool(T instance) {
            for (int i = 0; i < this.mPoolSize; i++) {
                if (this.mPool[i] == instance) {
                    return true;
                }
            }
            return false;
        }
    }
}
