#include <iostream>
#include <vector>
#include <algorithm>

const int MOD = 1000000007;

int power(int x, unsigned int y, int p) {
    int res = 1;
    x = x % p;
    while (y > 0) {
        if (y & 1)
            res = (int)((1LL * res * x) % p);
        y = y >> 1;
        x = (int)((1LL * x * x) % p);
    }
    return res;
}

int modInverse(int n, int p) {
    return power(n, p-2, p);
}

void ZigZag(int n) {
    std::vector<long long> fact(n + 1), invFact(n + 1), zig(n + 1, 0);
    fact[0] = invFact[0] = 1;
    for (int i = 1; i <= n; i++) {
        fact[i] = fact[i - 1] * i % MOD;
        invFact[i] = modInverse(fact[i], MOD);
    }

    zig[0] = 1;
    zig[1] = 1;

    for (int i = 2; i <= n; i++) {
        long long sum = 0;
        for (int k = 0; k < i; k++) {
            long long term = fact[i - 1] * invFact[k] % MOD * invFact[i - 1 - k] % MOD;
            term = term * zig[k] % MOD * zig[i - 1 - k] % MOD;
            sum = (sum + term) % MOD;
        }
        
        zig[i] = (sum * modInverse(2, MOD)) % MOD;
    }

    std::cout << zig[n] << std::endl;
}

int main() {
    int n;
    std::cin >> n;

    ZigZag(n);

    return 0;
}