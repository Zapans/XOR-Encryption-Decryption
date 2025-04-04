#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#define MAX_LENGTH 256

// Function to validate argument length
bool validateArgs(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strlen(argv[i]) > MAX_LENGTH) {
            return false;
        }
    }
    return true;
}

// Function to generate a simple hash
unsigned long generateHash(const std::string& text) {
    unsigned long hash = 0;
    for (char ch : text) {
        hash = (hash * 31) + ch;
    }
    return hash;
}

// Base64 Encoding
std::string base64Encode(const std::string& input) {
    static const char encodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    int val = 0, valb = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(encodingTable[(val >> valb) & 63]);
            valb -= 6;
        }
    }
    if (valb > -6) encoded.push_back(encodingTable[((val << 8) >> (valb + 8)) & 63]);
    while (encoded.size() % 4) encoded.push_back('=');
    return encoded;
}

// Base64 Decoding
std::string base64Decode(const std::string& input) {
    static const char decodingTable[] = {
        62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1,
        -1, -1, 0, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
        14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
        42, 43, 44, 45, 46, 47, 48, 49, 50, 51
    };
    std::string decoded;
    std::vector<int> buffer(4, 0);
    int val = 0, valb = -8;
    for (unsigned char c : input) {
        if (c == '=') break;
        if (c > 127 || decodingTable[c - 43] == -1) continue;
        val = (val << 6) + decodingTable[c - 43];
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(char((val >> valb) & 255));
            valb -= 8;
        }
    }
    return decoded;
}

// Function to verify user authentication
bool verifyUser() {
    std::string inputPass;
    std::cout << "Enter Security Key:";
    std::cin >> inputPass;

    unsigned long inputHash = generateHash(inputPass);

    unsigned long correctHash = 2267642325933444780;  // Replace with actual hash from Step 1

    if (inputHash == correctHash) {
        return true;
    }

    std::cout << "Access Denied!" << std::endl;
    return false;
}

// Function to perform XOR cipher encryption/decryption
std::string xorCipher(const std::string& data, const std::string& key) {
    std::string result = data;
    for (size_t i = 0; i < data.length(); i++) {
        result[i] ^= key[i % key.length()];
    }
    return result;
}

// Function to load a file into a string
std::string loadFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return "";
    }
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

// Function to save a string to a file
void saveFile(const std::string& filename, const std::string& content) {
    std::ofstream file(filename);
    if (!file) {
        std::cerr << "Error writing file: " << filename << std::endl;
        return;
    }
    file << content;
}

// Function to encrypt a file
void encryptFile(const std::string& input, const std::string& output, const std::string& keyFile) {
    std::string text = loadFile(input);
    if (text.empty()) {
        std::cout << "Nothing to encrypt." << std::endl;
        return;
    }
    std::string key = loadFile(keyFile);
    if (key.empty()) {
        std::cerr << "Key file is empty or not loaded properly!" << std::endl;
        return;
    }
    std::string encrypted = xorCipher(text, key);
    std::string encoded = base64Encode(encrypted);
    saveFile(output, std::to_string(generateHash(text)) + "\n" + encoded);
    std::cout << "File encrypted successfully!" << std::endl;
}

// Function to decrypt a file
void decryptFile(const std::string& input, const std::string& keyFile) {
    std::ifstream file(input);
    if (!file) {
        std::cerr << "Error reading file: " << input << std::endl;
        return;
    }
    std::string hashLine;
    std::getline(file, hashLine);
    std::string encoded((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    std::string key = loadFile(keyFile);
    std::string encrypted = base64Decode(encoded);
    std::string decrypted = xorCipher(encrypted, key);

    if (std::to_string(generateHash(decrypted)) == hashLine) {
        saveFile(input, decrypted);
        std::cout << "Decryption successful!" << std::endl;
    }
    else {
        std::cout << "Integrity check failed!" << std::endl;
    }
}


// Main function
int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cout << "Usage: <input> <output> <key>" << std::endl;
        return 1;
    }

    if (!validateArgs(argc, argv)) {
        std::cout << "Error: Argument too long." << std::endl;
        return 1;
    }

    if (!verifyUser()) {
        return 1;
    }

    while (true) {
        std::cout << "Options:\n1) Encrypt\n2) Decrypt\n3) Exit\n> ";
        int choice;
        std::cin >> choice;

        if (choice == 1) {
            encryptFile(argv[1], argv[2], argv[3]);
        }
        else if (choice == 2) {
            decryptFile(argv[2], argv[3]);
        }
        else if (choice == 3) {
            break;
        }
        else {
            std::cout << "Invalid selection! Try again." << std::endl;
        }
    }
    return 0;
}
