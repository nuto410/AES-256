#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <chrono>

using namespace std;
using namespace std::chrono;

// 定義S-box 和逆S-box
const unsigned char s_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const unsigned char inv_s_box[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// 定義輪常量
const unsigned char rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// 有限域乘法
unsigned char gmul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    unsigned char counter;
    unsigned char hi_bit_set;
    for (counter = 0; counter < 8; counter++) {
        if (b & 1) p ^= a;
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set) a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return p;
}

// 逆字節替換(逆S-box)
void inv_sub_bytes(unsigned char *state) {
    for (int i = 0; i < 16; ++i) {
        state[i] = inv_s_box[state[i]];
    }
}

// 逆行移位
void inv_shift_rows(unsigned char *state) {
    unsigned char tmp[16];

    // 第一行不移位
    tmp[0] = state[0];
    tmp[1] = state[13];
    tmp[2] = state[10];
    tmp[3] = state[7];

    // 第二行右移一位
    tmp[4] = state[4];
    tmp[5] = state[1];
    tmp[6] = state[14];
    tmp[7] = state[11];

    // 第三行右移两位
    tmp[8] = state[8];
    tmp[9] = state[5];
    tmp[10] = state[2];
    tmp[11] = state[15];

    // 第四行右移三位
    tmp[12] = state[12];
    tmp[13] = state[9];
    tmp[14] = state[6];
    tmp[15] = state[3];

    // 將結果複製回state數組
    for (int i = 0; i < 16; ++i) {
        state[i] = tmp[i];
    }
}

// 逆列混淆
void inv_mix_columns(unsigned char *state) {
    unsigned char tmp[16];
    for (int i = 0; i < 4; ++i) {
        tmp[i*4] = gmul(0x0e, state[i*4]) ^ gmul(0x0b, state[i*4+1]) ^ gmul(0x0d, state[i*4+2]) ^ gmul(0x09, state[i*4+3]);
        tmp[i*4+1] = gmul(0x09, state[i*4]) ^ gmul(0x0e, state[i*4+1]) ^ gmul(0x0b, state[i*4+2]) ^ gmul(0x0d, state[i*4+3]);
        tmp[i*4+2] = gmul(0x0d, state[i*4]) ^ gmul(0x09, state[i*4+1]) ^ gmul(0x0e, state[i*4+2]) ^ gmul(0x0b, state[i*4+3]);
        tmp[i*4+3] = gmul(0x0b, state[i*4]) ^ gmul(0x0d, state[i*4+1]) ^ gmul(0x09, state[i*4+2]) ^ gmul(0x0e, state[i*4+3]);
    }
    // 將結果複製回state數組
    for (int i = 0; i < 16; ++i) {
        state[i] = tmp[i];
    }
}

// 密鑰擴展
void key_expansion(const unsigned char *key, unsigned char *round_keys) {
    unsigned char temp[4];
    int i = 0;

    // 第一輪直接複製密鑰
    for (; i < 16; ++i) {
        round_keys[i] = key[i];
    }

    // 生成後續密鑰
    while (i < 176) {
        // 將前一個密鑰複製到temp
        for (int j = 0; j < 4; ++j) {
            temp[j] = round_keys[i - 4 + j];
        }

        // 每4輪進行一次密鑰擴展核心操作
        if (i % 16 == 0) {
            // 字循環
            // 左移一位
            unsigned char tmp = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = tmp;

            // 字節替換
            temp[0] = s_box[temp[0]];
            temp[1] = s_box[temp[1]];
            temp[2] = s_box[temp[2]];
            temp[3] = s_box[temp[3]];

            // 輪常量
            temp[0] ^= rcon[i / 16 - 1];
        }

        // 生成鑰密鑰
        for (unsigned char j = 0; j < 4; ++j) {
            round_keys[i] = round_keys[i - 16] ^ temp[j];
            ++i;
        }
    }
}

// 字節替換(S-box)
void sub_bytes(unsigned char *state) {
    for (int i = 0; i < 16; ++i) {
        state[i] = s_box[state[i]];
    }
}

// 行移位
void shift_rows(unsigned char *state) {
    unsigned char tmp[16];

    // 第一行不移位
    tmp[0] = state[0];
    tmp[1] = state[5];
    tmp[2] = state[10];
    tmp[3] = state[15];

    // 第二行左移一位
    tmp[4] = state[4];
    tmp[5] = state[9];
    tmp[6] = state[14];
    tmp[7] = state[3];

    // 第三行左移两位
    tmp[8] = state[8];
    tmp[9] = state[13];
    tmp[10] = state[2];
    tmp[11] = state[7];

    // 第四行左移三位
    tmp[12] = state[12];
    tmp[13] = state[1];
    tmp[14] = state[6];
    tmp[15] = state[11];

    // 將結果複製回state數組
    for (int i = 0; i < 16; ++i) {
        state[i] = tmp[i];
    }
}

// 列混淆
void mix_columns(unsigned char *state) {
    unsigned char tmp[16];
    for (int i = 0; i < 4; ++i) {
        tmp[i*4] = gmul(0x02, state[i*4]) ^ gmul(0x03, state[i*4+1]) ^ state[i*4+2] ^ state[i*4+3];
        tmp[i*4+1] = state[i*4] ^ gmul(0x02, state[i*4+1]) ^ gmul(0x03, state[i*4+2]) ^ state[i*4+3];
        tmp[i*4+2] = state[i*4] ^ state[i*4+1] ^ gmul(0x02, state[i*4+2]) ^ gmul(0x03, state[i*4+3]);
        tmp[i*4+3] = gmul(0x03, state[i*4]) ^ state[i*4+1] ^ state[i*4+2] ^ gmul(0x02, state[i*4+3]);
    }
    // 將結果複製回state數組
    for (int i = 0; i < 16; ++i) {
        state[i] = tmp[i];
    }
}

// 輪密鑰加
void add_round_key(unsigned char *state, const unsigned char *round_key) {
    for (int i = 0; i < 16; ++i) {
        state[i] ^= round_key[i];
    }
}

// AES加密
void aes_encrypt(const unsigned char *plaintext, const unsigned char *key, unsigned char *ciphertext, int key_size, bool print_round_data) {
    int num_rounds = (key_size / 4) + 6;
    unsigned char round_keys[176];
    key_expansion(key, round_keys);

    // 初始化狀態數組
    unsigned char state[16];
    for (int i = 0; i < 16; ++i) {
        state[i] = plaintext[i];
    }

    // 初始輪密鑰加
    add_round_key(state, key);

    // 128bits 進行9輪加密(總共10輪加密)
    // 192bits 進行11輪加密(總共12輪加密)
    // 256bits 進行13輪加密(總共14輪加密)
    for (int round = 1; round < num_rounds; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys + round * 16);

        // 根據參數決定是否打印每輪的數據
        if (print_round_data) {
            cout << "Round " << dec << round << " data: ";
            for (int i = 0; i < 16; ++i) {
                cout << hex << setw(2) << setfill('0') << (int)state[i] << " ";
            }
            cout << endl;
        }
    }

    // 最後一輪加密
    // 最後一輪不進行列混淆
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys + 160);

    if (print_round_data) {
            cout << "Final Round data: ";
            for (int i = 0; i < 16; ++i) {
                cout << hex << setw(2) << setfill('0') << (int)state[i] << " ";
            }
            cout << endl;
        }

    // 將最終狀態數組複製到密文數組
    for (int i = 0; i < 16; ++i) {
        ciphertext[i] = state[i];
    }
}

void aes_decrypt(const unsigned char *ciphertext, const unsigned char *key, unsigned char *plaintext, int key_size, bool print_round_data) {
    int num_rounds = (key_size / 4) + 6;
    unsigned char round_keys[176];
    key_expansion(key, round_keys);

    // 初始化狀態數組
    unsigned char state[16];
    for (int i = 0; i < 16; ++i) {
        state[i] = ciphertext[i];
    }

    // 初始輪密鑰加
    add_round_key(state, round_keys + 160);

    // 128bits 進行9輪解密(總共10輪解密)
    // 192bits 進行11輪解密(總共12輪解密)
    // 256bits 進行13輪解密(總共14輪解密)
    for (int round = num_rounds-1; round > 0; --round) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, round_keys + round * 16);
        inv_mix_columns(state);

        // 根據參數決定是否打印每輪的數據
        if (print_round_data) {
            cout << "Round " << dec << round << " data: ";
            for (int i = 0; i < 16; ++i) {
                cout << hex << setw(2) << setfill('0') << (int)state[i] << " ";
            }
            cout << endl;
        }
    }

    // 最後一輪解密
    // 最後一輪不進行列混淆
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, round_keys);

    if (print_round_data) {
            cout << "Final Round data: ";
            for (int i = 0; i < 16; ++i) {
                cout << hex << setw(2) << setfill('0') << (int)state[i] << " ";
            }
            cout << endl;
        }

    // 將最終狀態數組複製到明文數組
    for (int i = 0; i < 16; ++i) {
        plaintext[i] = state[i];
    }
}


// AES加密和解密函數聲明
void aes_encrypt(const unsigned char *plaintext, const unsigned char *key, unsigned char *ciphertext, int key_size, bool print_round_data);
void aes_decrypt(const unsigned char *ciphertext, const unsigned char *key, unsigned char *plaintext, int key_size, bool print_round_data);

// 判斷檔案內容是否符合128bits、192bits、256bits
bool checkFileContentLength(const string& content) {
    // 判斷 content 長度是否為 16、24 或 32
    return (content.length() == 16 || content.length() == 24 || content.length() == 32);
}

int main() {
    int choice;

    while (true){
        cout << "\nWelcome to AES encryption and decryption system" << endl;
        cout << "input your choice" << endl;
        cout << "1. encrypt. 2.decrypt. 3.encrypt and show round encrypt. 4.decrypt and show round decrypt. 5.exit" << endl;

        if (!(cin >> choice)) {
            cerr << "\nplease input a number" << endl;
            cin.clear();
            cin.ignore(100, '\n');
            continue;
        }
        cin.ignore();  // 清除緩衝區中的換行符號

        switch (choice) {
            case 1:{
                // encrypt
                cout << "Encrypting..." << endl;
                // 讀取密鑰文件
                string keyFilePath;
                cout << "please input your Key file path" << endl;
                getline(cin, keyFilePath);
                // string keyFilePath = "C:\\Users\\ccllab\\Desktop\\C++\\Key192.txt"; // 替換為實際的密鑰文件路徑

                std::ifstream keyFile(keyFilePath, std::ios::binary);
                if (!keyFile.is_open()) {
                    std::cerr << "can't open key file: " << keyFilePath << std::endl;
                    return 1;
                }

                // 獲取密鑰文件大小
                keyFile.seekg(0, std::ios::end);
                std::streampos keySize = keyFile.tellg();
                keyFile.seekg(0, std::ios::beg);

                if (keySize != 16 && keySize != 24 && keySize != 32) {
                    std::cerr << "key file size is not correct, expected 16, 24, or 32 bytes" << std::endl;
                    return 1;
                }

                // 讀取密鑰大小
                std::vector<unsigned char> key(keySize);
                keyFile.read(reinterpret_cast<char*>(key.data()), keySize);
                keyFile.close();

                // 讀取明文文件
                string plaintextFilePath;
                cout << "please input your Plaintext file path" << endl;
                getline(cin, plaintextFilePath);
                // string plaintextFilePath = "C:\\Users\\ccllab\\Desktop\\C++\\PlainText.txt"; // 替換為實際的明文文件路徑

                std::ifstream plaintextFile(plaintextFilePath, std::ios::binary);
                if (!plaintextFile.is_open()) {
                    std::cerr << "can't open plaintext file: " << plaintextFilePath << std::endl;
                    return 1;
                }

                // 獲取明文文件大小
                plaintextFile.seekg(0, std::ios::end);
                std::streampos plaintextSize = plaintextFile.tellg();
                plaintextFile.seekg(0, std::ios::beg);

                // 確保明文大小是16字節的整數倍
                if (plaintextSize % 16 != 0) {
                    std::cerr << "plaintext file size is not correct, expected multiple of 16 bytes" << std::endl;
                    std::cerr << "plaintext padding......" << std::endl;
                    size_t padding_length = 16 - plaintextSize % 16;
                    plaintextSize += padding_length;
                }

                // 讀取明文
                std::vector<unsigned char> plaintext(plaintextSize);
                plaintextFile.read(reinterpret_cast<char*>(plaintext.data()), plaintextSize);
                plaintextFile.close();

                // 加密過程
                std::vector<unsigned char> ciphertext(plaintextSize);
                auto start = high_resolution_clock::now();
                for (std::streampos i = 0; i < plaintextSize; i += 16) {
                    aes_encrypt(plaintext.data() + i, key.data(), ciphertext.data() + i, keySize, false);
                }

                auto end = high_resolution_clock::now();
                duration<double> duration = end - start;

                // 輸出加密結果並將其寫入文件
                string cfilePath;
                cout << "please input your output Ciphertext file path" << endl;
                getline(cin, cfilePath);
                // string cfilePath = "C:\\Users\\ccllab\\Desktop\\C++\\CipherText.txt"; // 替換為實際的密文文件路徑

                std::ofstream cfile(cfilePath, std::ios::binary);
                if (!cfile.is_open()) {
                    std::cerr << "can't open CipherText.txt" << std::endl;
                    return 1;
                }
                cfile.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
                cfile.close();

                std::cout << "already write in CipherText.txt" << std::endl;
                std::cout << std::endl;

                // 計算並打印加密運算效能
                double bytes_per_second = plaintextSize / duration.count();
                cout << "Encryption performance: " << bytes_per_second << " bytes/second" << endl;

                break;
            }
            case 2:{
                // decrypt
                cout << "Decrypting..." << endl;

                // 讀取密鑰文件
                string keyPath;
                cout << "please input your Key file path" << endl;
                getline(cin, keyPath);
                // string keyPath = "C:\\Users\\ccllab\\Desktop\\C++\\Key128.txt"; // 替換為實際的密鑰文件路徑

                std::ifstream keyFile(keyPath, std::ios::binary);
                if (!keyFile.is_open()) {
                    std::cerr << "can't open key file: " << keyPath << std::endl;
                    return 1;
                }

                // 獲取密鑰文件大小
                keyFile.seekg(0, std::ios::end);
                std::streampos keySize = keyFile.tellg();
                keyFile.seekg(0, std::ios::beg);

                if (keySize != 16 && keySize != 24 && keySize != 32) {
                    std::cerr << "key file size is not correct, expected 16, 24, or 32 bytes" << std::endl;
                    return 1;
                }

                // 讀取密鑰大小
                std::vector<unsigned char> key(keySize);
                keyFile.read(reinterpret_cast<char*>(key.data()), keySize);
                keyFile.close();

                // 從文本文件讀取密文並解密
                string cfilePath;
                cout << "please input your Ciphertext file path" << endl;
                getline(cin, cfilePath);
                // string cfilePath = "C:\\Users\\ccllab\\Desktop\\C++\\CipherText.txt"; // 替換為實際的密文文件路徑

                std::ifstream infile(cfilePath, std::ios::binary);
                if (!infile.is_open()) {
                    std::cerr << "can't open CipherText.txt" << std::endl;
                    return 1;
                }

                infile.seekg(0, ios::end);
                streampos ciphertextSize = infile.tellg();
                infile.seekg(0, ios::beg);

                vector<unsigned char> read_ciphertext(ciphertextSize);
                infile.read(reinterpret_cast<char*>(read_ciphertext.data()), read_ciphertext.size());
                infile.close();

                std::cout << "Cipher from txt:";
                for (std::size_t i = 0; i < read_ciphertext.size(); ++i) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)read_ciphertext[i] << " ";
                }
                std::cout << std::endl;

                string dfilePath;
                cout << "please input your output Decrypt file path" << endl;
                getline(cin, dfilePath);
                // string dfilePath = "C:\\Users\\ccllab\\Desktop\\C++\\Decrypt.txt"; // 替換為實際的解密文件路徑

                std::ofstream dFile(dfilePath);

                // 解密过程
                std::vector<unsigned char> decrypted_text(read_ciphertext.size());
                for (std::streampos i = 0; i < read_ciphertext.size(); i += 16) {
                    aes_decrypt(read_ciphertext.data() + i, key.data(), decrypted_text.data() + i, keySize, false);
                }

                // 输出解密结果
                // 將解密結果寫入文件
                std::cout << "decrypt: ";
                auto start = high_resolution_clock::now();
                for (std::size_t i = 0; i < decrypted_text.size(); ++i) {
                    std::cout << decrypted_text[i];
                    dFile << decrypted_text[i];
                }
                auto end = high_resolution_clock::now();
                duration<double> duration = end - start;
                // 關閉文件
                dFile.close();

                std::cout << std::endl;
                std::cout << "\nDecryption result has been written to decrypted file" << std::endl;
                std::cout << std::endl;

                // 計算並打印加密運算效能
                double bytes_per_second = read_ciphertext.size() / duration.count();
                cout << "Decryption performance: " << bytes_per_second << " bytes/second" << endl;
                

                break;
            }
                
            case 3:{
                // round encrypt
                cout << "Round encrypting..." << endl;

                // 讀取密鑰文件
                string keyFilePath;
                cout << "please input your Key file path" << endl;
                getline(cin, keyFilePath);
                // string keyFilePath = "C:\\Users\\ccllab\\Desktop\\C++\\Key.txt"; // 替換為實際的密鑰文件路徑

                std::ifstream keyFile(keyFilePath, std::ios::binary);
                if (!keyFile.is_open()) {
                    std::cerr << "can't open key file: " << keyFilePath << std::endl;
                    return 1;
                }

                // 獲取密鑰文件大小
                keyFile.seekg(0, std::ios::end);
                std::streampos keySize = keyFile.tellg();
                keyFile.seekg(0, std::ios::beg);

                if (keySize != 16 && keySize != 24 && keySize != 32) {
                    std::cerr << "key file size is not correct, expected 16, 24, or 32 bytes" << std::endl;
                    return 1;
                }

                // 讀取密鑰大小
                std::vector<unsigned char> key(keySize);
                keyFile.read(reinterpret_cast<char*>(key.data()), keySize);
                keyFile.close();

                // 讀取明文文件
                string plaintextFilePath;
                cout << "please input your Plaintext file path" << endl;
                getline(cin, plaintextFilePath);
                // string plaintextFilePath = "C:\\Users\\ccllab\\Desktop\\C++\\PlainText.txt"; // 替換為實際的明文文件路徑

                std::ifstream plaintextFile(plaintextFilePath, std::ios::binary);
                if (!plaintextFile.is_open()) {
                    std::cerr << "can't open plaintext file: " << plaintextFilePath << std::endl;
                    return 1;
                }

                // 獲取明文文件大小
                plaintextFile.seekg(0, std::ios::end);
                std::streampos plaintextSize = plaintextFile.tellg();
                plaintextFile.seekg(0, std::ios::beg);

                // 確保明文大小是16字節的整數倍
                if (plaintextSize % 16 != 0) {
                    std::cerr << "plaintext file size is not correct, expected multiple of 16 bytes" << std::endl;
                    std::cerr << "plaintext padding......" << std::endl;
                    size_t padding_length = 16 - plaintextSize % 16;
                    plaintextSize += padding_length;
                }

                // 讀取明文
                std::vector<unsigned char> plaintext(plaintextSize);
                plaintextFile.read(reinterpret_cast<char*>(plaintext.data()), plaintextSize);
                plaintextFile.close();

                // 加密過程
                std::vector<unsigned char> ciphertext(plaintextSize);
                auto start = high_resolution_clock::now();
                for (std::streampos i = 0; i < plaintextSize; i += 16) {
                    aes_encrypt(plaintext.data() + i, key.data(), ciphertext.data() + i, keySize, true);
                }

                auto end = high_resolution_clock::now();
                duration<double> duration = end - start;

                // 輸出加密結果並將其寫入文件
                string cfilePath;
                cout << "please input your output Ciphertext file path" << endl;
                getline(cin, cfilePath);
                // string cfilePath = "C:\\Users\\ccllab\\Desktop\\C++\\CipherText.txt"; // 替換為實際的密文文件路徑

                std::ofstream cfile(cfilePath, std::ios::binary);
                if (!cfile.is_open()) {
                    std::cerr << "can't open CipherText.txt" << std::endl;
                    return 1;
                }
                cfile.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
                cfile.close();

                std::cout << "already write in CipherText.txt" << std::endl;
                std::cout << std::endl;

                // 計算並打印加密運算效能
                double bytes_per_second = plaintextSize / duration.count();
                cout << "Encryption performance: " << bytes_per_second << " bytes/second" << endl;

                break;
            }
            case 4:{
                // round decrypt
                cout << "Round decrypting..." << endl;

                // 讀取密鑰文件
                string keyPath;
                cout << "please input your Key file path" << endl;
                getline(cin, keyPath);
                // string keyPath = "C:\\Users\\ccllab\\Desktop\\C++\\Key128.txt"; // 替換為實際的密鑰文件路徑

                std::ifstream keyFile(keyPath, std::ios::binary);
                if (!keyFile.is_open()) {
                    std::cerr << "can't open key file: " << keyPath << std::endl;
                    return 1;
                }

                // 獲取密鑰文件大小
                keyFile.seekg(0, std::ios::end);
                std::streampos keySize = keyFile.tellg();
                keyFile.seekg(0, std::ios::beg);

                if (keySize != 16 && keySize != 24 && keySize != 32) {
                    std::cerr << "key file size is not correct, expected 16, 24, or 32 bytes" << std::endl;
                    return 1;
                }

                // 讀取密鑰大小
                std::vector<unsigned char> key(keySize);
                keyFile.read(reinterpret_cast<char*>(key.data()), keySize);
                keyFile.close();

                 // 從文本文件讀取密文並解密
                string cfilePath;
                cout << "please input your Ciphertext file path" << endl;
                getline(cin, cfilePath);
                // string cfilePath = "C:\\Users\\ccllab\\Desktop\\C++\\CipherText.txt"; // 替換為實際的密文文件路徑

                std::ifstream infile(cfilePath, std::ios::binary);
                if (!infile.is_open()) {
                    std::cerr << "can't open CipherText.txt" << std::endl;
                    return 1;
                }

                infile.seekg(0, ios::end);
                streampos ciphertextSize = infile.tellg();
                infile.seekg(0, ios::beg);

                vector<unsigned char> read_ciphertext(ciphertextSize);
                infile.read(reinterpret_cast<char*>(read_ciphertext.data()), read_ciphertext.size());
                infile.close();

                std::cout << "Cipher from txt:";
                for (std::size_t i = 0; i < read_ciphertext.size(); ++i) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)read_ciphertext[i] << " ";
                }
                std::cout << std::endl;

                string dfilePath;
                cout << "please input your output Decrypt file path" << endl;
                getline(cin, dfilePath);
                // string dfilePath = "C:\\Users\\ccllab\\Desktop\\C++\\Decrypt.txt"; // 替換為實際的解密文件路徑

                std::ofstream dFile(dfilePath);

                // 解密过程
                std::vector<unsigned char> decrypted_text(read_ciphertext.size());
                for (std::streampos i = 0; i < read_ciphertext.size(); i += 16) {
                    aes_decrypt(read_ciphertext.data() + i, key.data(), decrypted_text.data() + i, keySize, true);
                }

                // 输出解密结果
                // 將解密結果寫入文件
                std::cout << "decrypt: ";
                auto start = high_resolution_clock::now();
                for (std::size_t i = 0; i < decrypted_text.size(); ++i) {
                    std::cout << decrypted_text[i];
                    dFile << decrypted_text[i];
                }
                auto end = high_resolution_clock::now();
                duration<double> duration = end - start;
                // 關閉文件
                dFile.close();

                std::cout << std::endl;
                std::cout << "\nDecryption result has been written to decrypted file" << std::endl;
                std::cout << std::endl;

                // 計算並打印加密運算效能
                double bytes_per_second = read_ciphertext.size() / duration.count();
                cout << "Decryption performance: " << bytes_per_second << " bytes/second" << endl;

                break;
            }
                
            case 5:{
                // 關閉程式
                cout << "Exiting..." << endl;
                return 0;
            }
                
            default:
                cout << "Invalid choice. Please try again." << endl;
                break;
    }

    }

    return 0;
}
