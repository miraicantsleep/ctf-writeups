#include <bits/stdc++.h>
using namespace std;

int main()
{
    string encrypted = "!?}De!e3d_5n_nipaOw_3eTR3bt4{_THB";
    string decrypted = "";

    for (int i = encrypted.size() - 1; i >= 0; i -= 3)
    {
        decrypted += encrypted[i - 1];
        decrypted += encrypted[i - 2];
        decrypted += encrypted[i];
    }

    cout << decrypted << endl;
    return 0;
}
