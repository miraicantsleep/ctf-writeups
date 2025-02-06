// g++ cryptology.cpp -o cryptology -lcryptopp

#include<iostream>
#include<fstream>
#include<vector>
#include<sstream>
#include<string>
#include<iomanip>
#include<fcntl.h>
#include<unistd.h>

#include <crypto++/modes.h>
#include <crypto++/aes.h>
#include <crypto++/filters.h>

struct AESMetadata {
    CryptoPP::byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ];
    CryptoPP::byte iv[ CryptoPP::AES::BLOCKSIZE ];
    AESMetadata* nextAESMetadata;
};

int urandom_fd;
AESMetadata* headAESMetadata;

void init() {
    setvbuf(stdout, NULL, _IONBF, 0);
    headAESMetadata = new AESMetadata();
    if(headAESMetadata == nullptr) {
        std::cout << "Error, contact admin" << std::endl;
        exit(-1);
    }
    headAESMetadata->nextAESMetadata = nullptr;
    urandom_fd = open("/dev/urandom", O_RDONLY);
    if(urandom_fd < 0) {
        std::cout << "Error, contact admin" << std::endl;
        exit(-1);
    }
    return;
}

void menu() {
    std::cout << "1. Encrypt file" << std::endl;
    std::cout << "2. Decrypt file" << std::endl;
    std::cout << "3. Create new AES Key" << std::endl;
    std::cout << "4. Exit" << std::endl;
    std::cout << "> ";
}

uint64_t aes_metadata_count() {

    uint64_t count = 0;
    AESMetadata* tmp = headAESMetadata->nextAESMetadata;
    while(tmp != nullptr) {
        count++;
        tmp = tmp->nextAESMetadata;
    }
    return count;
}

AESMetadata* get_aes_metadata() {
    uint64_t choice = 0, max_index = aes_metadata_count();
    std::cout << "AES key index (1-" << max_index << "): ";
    std::cin >> choice;
    if(choice < 1 || choice > max_index) {
        return nullptr;
    }
    AESMetadata* res = headAESMetadata;
    for(uint64_t i = 0; i < choice; i++) res = res->nextAESMetadata;
    return res; }

void encrypt() {

    if(aes_metadata_count() < 1) {
        std::cout << "Create an AES metadata first!" << std::endl;
        return;
    }

    uint64_t data_length;
    std::string plaintext, ciphertext;
    std::cout << "Enter data length: ";
    std::cin >> data_length;
    std::cin.clear();
    std::cin.ignore(INT_MAX,'\n');
    char* data = new char[data_length+1];
    if(data == nullptr) {
        std::cout << "Error!" << std::endl;
        return;
    }
    std::cout << "Enter string to encrypt: ";
    std::cin.read(data, data_length);
    plaintext = data;
    plaintext[data_length] = '\0';
    std::cin.clear();
    std::cin.ignore(INT_MAX,'\n');
    delete[] data;
    data = nullptr;

    AESMetadata* aesMetadata = get_aes_metadata();
    if(aesMetadata == nullptr) {
        std::cout << "Invalid AES metadata!" << std::endl;
        return;
    }
    
    std::string filename;
    std::cout << "Enter filename: ";
    std::cin >> filename;
    if(filename == "") {
        std::cout << "Invalid filename!" << std::endl;
        return;
    }
    plaintext.resize((plaintext.length() + 0xf) & 0xfffffffffffffff0);
    
    CryptoPP::AES::Encryption aesEncryption(aesMetadata->key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, aesMetadata->iv);

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext), CryptoPP::StreamTransformationFilter::NO_PADDING);
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
    stfEncryptor.MessageEnd();
    
    std::ofstream out(filename.c_str());
    out << ciphertext; 
    if(out.bad()) {
        std::cout << "Writing to file error" << std::endl;
        return;
    }

    std::cout << "Done!" << std::endl;
    return;
}

void decrypt() {

    if(aes_metadata_count() < 1) {
        std::cout << "Create an AES metadata first!" << std::endl;
        return;
    }

    AESMetadata* aesMetadata = get_aes_metadata();
    if(aesMetadata == nullptr) {
        std::cout << "Invalid AES metadata!" << std::endl;
        return;
    }
    
    std::string filename;
    std::cout << "Enter filename: ";
    std::cin >> filename;
    if(filename == "") {
        std::cout << "Invalid filename!" << std::endl;
        return;
    }

    std::string ciphertext, plaintext;
    char tmp;
    std::ifstream in(filename.c_str());
    while(in.read(&tmp, 1)) {
        ciphertext += tmp;
    }
    if(in.bad()) {
        std::cout << "Reading from file error" << std::endl;
        return;
    }
    ciphertext.resize((ciphertext.length() + 0xf) & 0xfffffffffffffff0);
    
    CryptoPP::AES::Decryption aesDecryption(aesMetadata->key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, aesMetadata->iv);

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(plaintext), CryptoPP::StreamTransformationFilter::NO_PADDING);
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size());
    stfDecryptor.MessageEnd();

    std::cout << "Decrypted text: ";
    for(int i = 0; i < plaintext.length(); i++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (((int) plaintext[i]) & 0xff);
    }
    std::cout << std::endl;
}

void generate_random(CryptoPP::byte *buf, int size) {
    read(urandom_fd, buf, size);
}

void add_aes_metadata() {
    AESMetadata* newAESMetadata = new AESMetadata();
    if(newAESMetadata == nullptr) {
        std::cout << "Error, contact admin" << std::endl;
        exit(-1);
    }
    newAESMetadata ->nextAESMetadata = nullptr;
    generate_random(newAESMetadata->key, sizeof(newAESMetadata->key));
    generate_random(newAESMetadata->iv, sizeof(newAESMetadata->iv));

    AESMetadata* tmp = headAESMetadata;
    while(tmp->nextAESMetadata != nullptr) tmp = tmp->nextAESMetadata;
    tmp->nextAESMetadata = newAESMetadata;

    std::cout << "New AES Key and IV generated!" << std::endl;
}

int main(int argc, char* argv[]) {
    uint choice;
    init();

    while(1)    {
        menu();
        choice = 0;
        std::cin >> choice;
        std::cin.clear();
        std::cin.ignore(INT_MAX,'\n');
        switch(choice)  {
            case 1:
                encrypt();
                break;
            case 2:
                decrypt();
                break;
            case 3:
                add_aes_metadata();
                break;
            case 4:
                std::cout << "Bye bye!" << std::endl;
                return 0;
            default:
                std::cout << "Error!" << std::endl;
                return 0;
        }
    }
    return 0;
}

