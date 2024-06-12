#include <bits/stdc++.h>
#include <assert.h>
using namespace std;

void solve()
{
    string s = "Fcn_yDlvaGpj_Logi}eias{iaeAm_s";
    string decoded = "miraimiraimiraimiraimiraimirai";

    assert(s.size() == decoded.size());
    
    for (int i = 0; i < s.size(); i++)
    {
        decoded[(i * 7) % 30] = s[i];
    }

    if (decoded.find("FLAG") != string::npos)
    {
        cout << "Found flag: " << decoded << endl;
    }
    else
    {
        cout << "bruh\n";
    }
}

int main(int argc, char const *argv[])
{
    int t = 1;
    // cin >> t;
    while (t--)
    {
        solve();
    }

    return 0;
}
