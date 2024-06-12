#include <bits/stdc++.h>
using namespace std;

void solve(const vector<char>& encoded, string& decoded) {
    decoded.resize(encoded.size());
    decoded[0] = encoded[0];
    for (size_t i = 1; i < encoded.size(); i++) {
        decoded[i] = encoded[i] ^ encoded[i - 1];
    }
}

int main() {
    string input = "4717591a4e08732410215579264e7e0956320367384171045b28187402316e1a7243300f501946325a6a1f7810643b0a7e21566257083c63043404603f5763563e43";
    vector<char> encoded(input.length() / 2);
    string decoded;

    for (size_t i = 0; i < encoded.size(); i++) {
        stringstream hexStream(input.substr(2 * i, 2));
        int value;
        hexStream >> hex >> value;
        encoded[i] = static_cast<char>(value);
    }

    solve(encoded, decoded);
    cout << decoded << endl;

    return 0;
}
