// Dear ImGui: standalone example application for DirectX 9

// Learn about Dear ImGui:
// - FAQ                  https://dearimgui.com/faq
// - Getting Started      https://dearimgui.com/getting-started
// - Documentation        https://dearimgui.com/docs (same as your local docs/ folder).
// - Introduction, links and more at the top of imgui.cpp

#include "imgui.h"
#include "imgui_impl_dx9.h"
#include "imgui_impl_win32.h"
#include <d3d9.h>
#include <tchar.h>
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

// Data
static LPDIRECT3D9              g_pD3D = nullptr;
static LPDIRECT3DDEVICE9        g_pd3dDevice = nullptr;
static UINT                     g_ResizeWidth = 0, g_ResizeHeight = 0;
static D3DPRESENT_PARAMETERS    g_d3dpp = {};
std::vector<std::string> logtext; // 保存按鈕按下後的文字
char inputText1[256] = ""; // 用於保存用戶輸入的文本1
char inputText2[256] = ""; // 用於保存用戶輸入的文本2
char inputText3[256] = ""; // 用於保存用戶輸入的文本3
bool inputCompleted = false; // 用於標記用戶是否完成輸入
bool showEncryptInputText = false;      // 控制第一个按钮的输入框显示
bool showDecryptInputText = false;      // 控制第二个按钮的输入框显示
bool RoundE = false;
bool RoundD = false;

// Forward declarations of helper functions
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void ResetDevice();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);



//AES

// 定義S-box和逆S-box
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

// 逆字節替換
void inv_sub_bytes(unsigned char* state) {
    for (int i = 0; i < 16; ++i) {
        state[i] = inv_s_box[state[i]];
    }
}

// 逆行移位
void inv_shift_rows(unsigned char* state) {
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
void inv_mix_columns(unsigned char* state) {
    unsigned char tmp[16];
    for (int i = 0; i < 4; ++i) {
        tmp[i * 4] = gmul(0x0e, state[i * 4]) ^ gmul(0x0b, state[i * 4 + 1]) ^ gmul(0x0d, state[i * 4 + 2]) ^ gmul(0x09, state[i * 4 + 3]);
        tmp[i * 4 + 1] = gmul(0x09, state[i * 4]) ^ gmul(0x0e, state[i * 4 + 1]) ^ gmul(0x0b, state[i * 4 + 2]) ^ gmul(0x0d, state[i * 4 + 3]);
        tmp[i * 4 + 2] = gmul(0x0d, state[i * 4]) ^ gmul(0x09, state[i * 4 + 1]) ^ gmul(0x0e, state[i * 4 + 2]) ^ gmul(0x0b, state[i * 4 + 3]);
        tmp[i * 4 + 3] = gmul(0x0b, state[i * 4]) ^ gmul(0x0d, state[i * 4 + 1]) ^ gmul(0x09, state[i * 4 + 2]) ^ gmul(0x0e, state[i * 4 + 3]);
    }
    // 將結果複製回state數組
    for (int i = 0; i < 16; ++i) {
        state[i] = tmp[i];
    }
}

// 密鑰擴展
void key_expansion(const unsigned char* key, unsigned char* round_keys, int key_size) {
    int num_rounds = (key_size / 4) + 6;
    int key_length = key_size / 8; // 密鑰長度(字節)
    int expanded_key_size = 16 * (num_rounds + 1); // 擴展密鑰的長度(字節)

    unsigned char temp[4];
    int i = 0;

    // 複製初始密鑰
    for (; i < key_length; ++i) {
        round_keys[i] = key[i];
    }

    // 生成後續輪密鑰
    while (i < expanded_key_size) {
        for (int j = 0; j < 4; ++j) {
            temp[j] = round_keys[(i - 4) + j];
        }

        if (i % key_length == 0) {
            // 字循環
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
            temp[0] ^= rcon[(i / key_length) - 1];
        }

        if (key_size == 256 && i % key_length == 16) {
            for (int j = 0; j < 4; ++j) {
                temp[j] = s_box[temp[j]];
            }
        }

        for (int j = 0; j < 4; ++j) {
            round_keys[i] = round_keys[i - key_length] ^ temp[j];
            ++i;
        }
    }
}

// 字節替換(S-box)
void sub_bytes(unsigned char* state) {
    for (int i = 0; i < 16; ++i) {
        state[i] = s_box[state[i]];
    }
}

// 行移位
void shift_rows(unsigned char* state) {
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
void mix_columns(unsigned char* state) {
    unsigned char tmp[16];
    for (int i = 0; i < 4; ++i) {
        tmp[i * 4] = gmul(0x02, state[i * 4]) ^ gmul(0x03, state[i * 4 + 1]) ^ state[i * 4 + 2] ^ state[i * 4 + 3];
        tmp[i * 4 + 1] = state[i * 4] ^ gmul(0x02, state[i * 4 + 1]) ^ gmul(0x03, state[i * 4 + 2]) ^ state[i * 4 + 3];
        tmp[i * 4 + 2] = state[i * 4] ^ state[i * 4 + 1] ^ gmul(0x02, state[i * 4 + 2]) ^ gmul(0x03, state[i * 4 + 3]);
        tmp[i * 4 + 3] = gmul(0x03, state[i * 4]) ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ gmul(0x02, state[i * 4 + 3]);
    }
    // 將結果複製回state數組
    for (int i = 0; i < 16; ++i) {
        state[i] = tmp[i];
    }
}

// 輪密鑰加
void add_round_key(unsigned char* state, const unsigned char* round_key) {
    for (int i = 0; i < 16; ++i) {
        state[i] ^= round_key[i];
    }
}


// 打印狀態數組
void print_state(const string& label, const unsigned char* state) {
    std::stringstream ss;
    ss << label << ": ";
    for (int i = 0; i < 16; ++i) {
        ss << hex << setw(2) << setfill('0') << (int)state[i] << " ";
    }
    logtext.push_back(ss.str());
}


// AES加密函数
void aes_encrypt(const unsigned char* plaintext, const unsigned char* key, unsigned char* ciphertext, int key_size, bool print_round_data) {
    int num_rounds = (key_size / 32) + 6;
    unsigned char round_keys[240]; // 最大需要 240 字節用於256位密鑰
    key_expansion(key, round_keys, key_size);

    // 初始化狀態數組
    unsigned char state[16];
    for (int i = 0; i < 16; ++i) {
        state[i] = plaintext[i];
    }

    // 初始輪密鑰加
    add_round_key(state, round_keys);
    if (print_round_data) {
        print_state("After initial AddRoundKey", state);
    }

    // 進行 (num_rounds - 1) 輪加密
    for (int round = 1; round < num_rounds; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys + round * 16);

        // 根據參數決定是否打印每輪的數據
        if (print_round_data) {
            print_state("After round " + to_string(round), state);
        }
    }

    // 最後一輪加密(不進行列混淆)
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys + num_rounds * 16);

    if (print_round_data) {
        print_state("Final Round data", state);
    }

    // 將最終狀態數組複製到密文數組
    for (int i = 0; i < 16; ++i) {
        ciphertext[i] = state[i];
    }
}

void aes_decrypt(const unsigned char* ciphertext, const unsigned char* key, unsigned char* plaintext, int key_size, bool print_round_data) {
    int num_rounds = (key_size / 32) + 6;
    unsigned char round_keys[240]; // 最大需要 240 字節用於256位密鑰
    key_expansion(key, round_keys, key_size);

    // 初始化狀態數組
    unsigned char state[16];
    for (int i = 0; i < 16; ++i) {
        state[i] = ciphertext[i];
    }

    // 初始輪密鑰加
    add_round_key(state, round_keys + num_rounds * 16);
    if (print_round_data) {
        print_state("After initial AddRoundKey", state);
    }

    // 進行 (num_rounds - 1) 輪解密
    for (int round = num_rounds - 1; round > 0; --round) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, round_keys + round * 16);
        inv_mix_columns(state);

        // 根據參數決定是否打印每輪的數據
        if (print_round_data) {
            print_state("After round " + to_string(round), state);
        }
    }

    // 最後一輪解密(不進行逆列混淆)
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, round_keys);

    if (print_round_data) {
        print_state("Final Round data", state);
    }

    // 將最終狀態數組複製到明文數組
    for (int i = 0; i < 16; ++i) {
        plaintext[i] = state[i];
    }
}

// AES加密和解密函數聲明
void aes_encrypt(const unsigned char* plaintext, const unsigned char* key, unsigned char* ciphertext, int key_size, bool print_round_data);
void aes_decrypt(const unsigned char* ciphertext, const unsigned char* key, unsigned char* plaintext, int key_size, bool print_round_data);

// 判斷檔案內容是否符合128bits、192bits、256bits
bool checkFileContentLength(const string& content, bool roundprint) {
    // 判斷 content 長度是否為 16、24 或 32
    return (content.length() == 16 || content.length() == 24 || content.length() == 32);
}

void Encrypt(const std::string& input1, const std::string& input2, const std::string& input3, bool input4) {
    try {
        // encrypt
        std::stringstream ss;
        logtext.push_back("Encrypting...");
        // 讀取密鑰文件
        //string keyFilePath = "C:\\Users\\ccllab\\Desktop\\C++\\Key128.txt"; // 替換為實際的密鑰檔案路徑
        string keyFilePath = input2;
        std::ifstream keyFile(keyFilePath, std::ios::binary);
        if (!keyFile.is_open()) {
            std::stringstream ss;
            ss << keyFilePath;
            logtext.push_back("can't open key file: " + ss.str() + "\n");
        }

        // 獲取密鑰文件大小
        keyFile.seekg(0, std::ios::end);
        std::streampos keySize = keyFile.tellg();
        keyFile.seekg(0, std::ios::beg);

        if (keySize != 16 && keySize != 24 && keySize != 32) {
            logtext.push_back("key file size is not correct, expected 16, 24, or 32 bytes");
        }

        // 讀取密鑰
        std::vector<unsigned char> key(keySize);
        keyFile.read(reinterpret_cast<char*>(key.data()), keySize);
        keyFile.close();

        // 讀取明文文件
        //string plaintextFilePath = "C:\\Users\\ccllab\\Desktop\\C++\\PlainText.txt"; // 替換為實際的明文檔案路徑
        string plaintextFilePath = input1;
        std::ifstream plaintextFile(plaintextFilePath, std::ios::binary);
        if (!plaintextFile.is_open()) {
            std::stringstream ss;
            ss << plaintextFilePath;
            logtext.push_back("can't open plaintext file: " + ss.str() + "\n");
        }

        // 獲取文件大小
        plaintextFile.seekg(0, std::ios::end);
        std::streampos plaintextSize = plaintextFile.tellg();
        plaintextFile.seekg(0, std::ios::beg);

        // 確保明文大小是16字節的整數倍
        if (plaintextSize % 16 != 0) {
            logtext.push_back("plaintext file size is not correct, expected multiple of 16 bytes.\n");
            logtext.push_back("plaintext padding......\n");

            size_t padding_length = 16 - plaintextSize % 16;
            plaintextSize += padding_length;
        }

        // 讀取明文
        std::vector<unsigned char> plaintext(plaintextSize);
        plaintextFile.read(reinterpret_cast<char*>(plaintext.data()), plaintextSize);
        plaintextFile.close();

        // 加密過程
        std::vector<unsigned char> ciphertext(plaintextSize);
        bool roundprint = input4;
        auto start = high_resolution_clock::now();
        for (std::streampos i = 0; i < plaintextSize; i += 16) {
            aes_encrypt(plaintext.data() + i, key.data(), ciphertext.data() + i, keySize, roundprint);
        }
        auto end = high_resolution_clock::now();
        duration<double> duration = end - start;

        // 輸出加密結果並將其寫入文件
        //string cfilePath = "C:\\Users\\ccllab\\Desktop\\C++\\CipherText.txt"; // 替換為實際的密文文件路徑
        string cfilePath = input3;
        std::ofstream cfile(cfilePath, std::ios::binary);
        if (!cfile.is_open()) {
            logtext.push_back("can't open CipherText.txt\n");
        }

        cfile.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
        cfile.close();


        logtext.push_back("already write in CipherText.txt\n\n");
        std::stringstream ss3;
        ss3 << duration.count();
        logtext.push_back("Encryption performance: " + ss3.str() + " bytes/second");
    }
    catch (const std::exception& e) {
        std::stringstream ss;
        std::cerr << "Exception: " << e.what() << std::endl;
        ss << "Exception: " << e.what() << std::endl;
        logtext.push_back(ss.str());
    }

}

void Decrypt(const std::string& input1, const std::string& input2, const std::string& input3, bool input4) {
    try {
        logtext.push_back("Decrypting...\n");

        // 讀取密鑰文件
        string keyPath = input2;
        //string keyPath = "C:\\Users\\ccllab\\Desktop\\C++\\Key128.txt"; // 替換為實際的密鑰文件路徑
        std::ifstream keyFile(keyPath, std::ios::binary);
        if (!keyFile.is_open()) {
            logtext.push_back("can't open key file\n");
        }

        // 獲取密鑰文件大小
        keyFile.seekg(0, std::ios::end);
        std::streampos keySize = keyFile.tellg();
        keyFile.seekg(0, std::ios::beg);

        if (keySize != 16 && keySize != 24 && keySize != 32) {
            std::stringstream ss;
            ss << "your key file is " << keySize << " bytes";
            logtext.push_back(ss.str() + "\n");
            logtext.push_back("key file size is not correct, expected 16, 24, or 32 bytes\n");
        }

        // 讀取密鑰大小
        std::vector<unsigned char> key(keySize);
        keyFile.read(reinterpret_cast<char*>(key.data()), keySize);
        keyFile.close();

        // 從文本文件讀取密文並解密
        string cfilePath = input1;
        //string cfilePath = "C:\\Users\\ccllab\\Desktop\\C++\\CipherText.txt"; // 替換為實際的密文文件路徑
        std::ifstream infile(cfilePath, std::ios::binary);
        if (!infile.is_open()) {
            logtext.push_back("can't open CipherText.txt\n");
        }

        infile.seekg(0, ios::end);
        streampos ciphertextSize = infile.tellg();
        infile.seekg(0, ios::beg);

        vector<unsigned char> read_ciphertext(ciphertextSize);
        infile.read(reinterpret_cast<char*>(read_ciphertext.data()), read_ciphertext.size());
        infile.close();

        std::stringstream ss2;
        logtext.push_back("Cipher from txt:\n");
        for (std::size_t i = 0; i < read_ciphertext.size(); ++i) {

            ss2 << std::hex << std::setw(2) << std::setfill('0') << (int)read_ciphertext[i] << " ";

        }
        logtext.push_back(ss2.str());
        logtext.push_back("\n");

        string dfilePath = input3;
        bool roundprint = input4;
        //string dfilePath = "C:\\Users\\ccllab\\Desktop\\C++\\Decrypt.txt"; // 替換為實際的解密文件路徑

        std::ofstream dFile(dfilePath);

        // 解密过程

        std::vector<unsigned char> decrypted_text(read_ciphertext.size());
        for (std::streampos i = 0; i < read_ciphertext.size(); i += 16) {
            aes_decrypt(read_ciphertext.data() + i, key.data(), decrypted_text.data() + i, keySize, roundprint);
        }

        // 输出解密结果
        // 將解密結果寫入文件
        cout << "keysize" << keySize;
        std::stringstream ss4;
        logtext.push_back("decrypt: \n");
        auto start = high_resolution_clock::now();
        for (std::size_t i = 0; i < decrypted_text.size(); ++i) {
            std::stringstream ss;
            ss4 << decrypted_text[i];
            dFile << decrypted_text[i];
        }
        logtext.push_back(ss4.str());
        auto end = high_resolution_clock::now();
        duration<double> duration = end - start;
        // 關閉文件
        dFile.close();

        logtext.push_back("\nDecryption result has been written to decrypted file\n");

        std::stringstream ss3;
        ss3 << duration.count();
        logtext.push_back("Encryption performance: " + ss3.str() + " bytes/second");
    }
    catch (const std::exception& e) {
        std::stringstream ss;
        std::cerr << "Exception: " << e.what() << std::endl;
        ss << "Exception: " << e.what() << std::endl;
        logtext.push_back(ss.str());
    }

}




// Main code

int main(int, char**)
{
    // Create application window
    //ImGui_ImplWin32_EnableDpiAwareness();
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"ImGui Example", nullptr };
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"Dear ImGui DirectX9 Example", WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, nullptr, nullptr, wc.hInstance, nullptr);

    // Initialize Direct3D
    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    // Show the window
    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;     // Enable Keyboard Controls
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;      // Enable Gamepad Controls

    // Setup Dear ImGui style
    ImGui::StyleColorsDark();
    //ImGui::StyleColorsLight();

    // Setup Platform/Renderer backends
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX9_Init(g_pd3dDevice);

    // Our state
    bool show_demo_window = true;
    bool show_another_window = false;
    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

    // Main loop
    bool done = false;
    while (!done)
    {
        // Poll and handle messages (inputs, window resize, etc.)
        // See the WndProc() function below for our to dispatch events to the Win32 backend.
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done)
            break;

        // Handle window resize (we don't resize directly in the WM_SIZE handler)
        if (g_ResizeWidth != 0 && g_ResizeHeight != 0)
        {
            g_d3dpp.BackBufferWidth = g_ResizeWidth;
            g_d3dpp.BackBufferHeight = g_ResizeHeight;
            g_ResizeWidth = g_ResizeHeight = 0;
            ResetDevice();
        }

        // Start the Dear ImGui frame
        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        {
            static int counter = 0;

            ImGui::Begin("AES Project");                          // Create a window called "Hello, world!" and append into it.


            if (ImGui::Button("Encrypt"))                            // Buttons return true when clicked (most widgets return true when edited/activated)
            {
                showEncryptInputText = true;
                showDecryptInputText = false;
                RoundE = false;
            }
            ImGui::SameLine();
            if (ImGui::Button("Decrypt"))                            // Buttons return true when clicked (most widgets return true when edited/activated)
            {
                showEncryptInputText = false;
                showDecryptInputText = true;
                RoundD = false;
            }
            ImGui::SameLine();
            if (ImGui::Button("Round Encrypt"))                            // Buttons return true when clicked (most widgets return true when edited/activated)
            {
                showEncryptInputText = true;
                showDecryptInputText = false;
                RoundE = true;
            }
            ImGui::SameLine();
            if (ImGui::Button("Round Decrypt"))                            // Buttons return true when clicked (most widgets return true when edited/activated)
            {
                showEncryptInputText = false;
                showDecryptInputText = true;
                RoundD = true;
            }


            if (ImGui::Button("Clear log")) {
                logtext.clear(); // 清除日誌向量
            }


            if (showEncryptInputText) {
                ImGui::Text("For example: C:\\\\user\\\\usr\\\\Plain.txt\n");

                ImGui::Text("PlainText file location     ");
                ImGui::SameLine();
                ImGui::InputText("##PlainText file location", inputText1, IM_ARRAYSIZE(inputText1));
                ImGui::Text("Key file location           ");
                ImGui::SameLine();
                ImGui::InputText("##Key file location ", inputText2, IM_ARRAYSIZE(inputText2));
                ImGui::Text("Output Cipher file location ");
                ImGui::SameLine();
                ImGui::InputText("##Output Cipher file location ", inputText3, IM_ARRAYSIZE(inputText3));

                if (ImGui::Button("Submit Encrypt")) {
                    showEncryptInputText = false; // 按下Submit按钮时隐藏输入框
                    std::string userInput1 = std::string(inputText1);
                    std::string userInput2 = std::string(inputText2);
                    std::string userInput3 = std::string(inputText3);
                    logtext.push_back("PlainText file location: " + userInput1);
                    logtext.push_back("Key file location: " + userInput2);
                    logtext.push_back("Output Cipher file location: " + userInput3);
                    Encrypt(userInput1, userInput2, userInput3, RoundE); // 调用加密函数
                }
            }

            if (showDecryptInputText) {
                ImGui::Text("For example: C:\\\\user\\\\usr\\\\Plain.txt\n");

                ImGui::Text("CipherText file location     ");
                ImGui::SameLine();
                ImGui::InputText("##CipherText file location", inputText1, IM_ARRAYSIZE(inputText1));
                ImGui::Text("Key file location            ");
                ImGui::SameLine();
                ImGui::InputText("##Key file location ", inputText2, IM_ARRAYSIZE(inputText2));
                ImGui::Text("Output Decrypt file location ");
                ImGui::SameLine();
                ImGui::InputText("##Output Decrypt file location ", inputText3, IM_ARRAYSIZE(inputText3));

                if (ImGui::Button("Submit Decrypt")) {
                    showDecryptInputText = false; // 按下Submit按钮时隐藏输入框
                    std::string userInput1 = std::string(inputText1);
                    std::string userInput2 = std::string(inputText2);
                    std::string userInput3 = std::string(inputText3);
                    logtext.push_back("CipherText file location: " + userInput1);
                    logtext.push_back("Key file location: " + userInput2);
                    logtext.push_back("Output Decrypt file location: " + userInput3);
                    Decrypt(userInput1, userInput2, userInput3, RoundD); // 调用加密函数
                }
            }




            //ImGui::SetNextWindowPos(ImVec2(350, 350)); // 设置窗口初始位置
            //ImGui::SetNextWindowSize(ImVec2(800, 600), ImGuiCond_FirstUseEver); // 设置窗口初始大小为 800x600
            ImGui::Begin("Log"); // 開始一个新的 ImGui 窗口，名稱为 "Log"
            for (const auto& entry : logtext) {
                ImGui::Text("%s", entry.c_str()); // 在窗口中顯示 logtext 内容
            }
            ImGui::End();



        }

        // Rendering
        ImGui::EndFrame();
        g_pd3dDevice->SetRenderState(D3DRS_ZENABLE, FALSE);
        g_pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
        g_pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);
        D3DCOLOR clear_col_dx = D3DCOLOR_RGBA((int)(clear_color.x * clear_color.w * 255.0f), (int)(clear_color.y * clear_color.w * 255.0f), (int)(clear_color.z * clear_color.w * 255.0f), (int)(clear_color.w * 255.0f));
        g_pd3dDevice->Clear(0, nullptr, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, clear_col_dx, 1.0f, 0);
        if (g_pd3dDevice->BeginScene() >= 0)
        {
            ImGui::Render();
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
            g_pd3dDevice->EndScene();
        }
        HRESULT result = g_pd3dDevice->Present(nullptr, nullptr, nullptr, nullptr);

        // Handle loss of D3D9 device
        if (result == D3DERR_DEVICELOST && g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET)
            ResetDevice();
    }

    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}

// Helper functions

bool CreateDeviceD3D(HWND hWnd)
{
    if ((g_pD3D = Direct3DCreate9(D3D_SDK_VERSION)) == nullptr)
        return false;

    // Create the D3DDevice
    ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
    g_d3dpp.Windowed = TRUE;
    g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN; // Need to use an explicit format with alpha if needing per-pixel alpha composition.
    g_d3dpp.EnableAutoDepthStencil = TRUE;
    g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
    g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;           // Present with vsync
    //g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;   // Present without vsync, maximum unthrottled framerate
    if (g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hWnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &g_d3dpp, &g_pd3dDevice) < 0)
        return false;

    return true;
}

void CleanupDeviceD3D()
{
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
    if (g_pD3D) { g_pD3D->Release(); g_pD3D = nullptr; }
}

void ResetDevice()
{
    ImGui_ImplDX9_InvalidateDeviceObjects();
    HRESULT hr = g_pd3dDevice->Reset(&g_d3dpp);
    if (hr == D3DERR_INVALIDCALL)
        IM_ASSERT(0);
    ImGui_ImplDX9_CreateDeviceObjects();
}

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Win32 message handler
// You can read the io.WantCaptureMouse, io.WantCaptureKeyboard flags to tell if dear imgui wants to use your inputs.
// - When io.WantCaptureMouse is true, do not dispatch mouse input data to your main application, or clear/overwrite your copy of the mouse data.
// - When io.WantCaptureKeyboard is true, do not dispatch keyboard input data to your main application, or clear/overwrite your copy of the keyboard data.
// Generally you may always pass all inputs to dear imgui, and hide them from your application based on those two flags.
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED)
            return 0;
        g_ResizeWidth = (UINT)LOWORD(lParam); // Queue resize
        g_ResizeHeight = (UINT)HIWORD(lParam);
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
