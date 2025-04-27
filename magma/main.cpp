#include "magma.h"
#include <iostream>
#include <iomanip>

int main() {
    try {
        Magma cipher;
        
        // Ключ 256 бит (32 байта)
        std::vector<unsigned char> key = {
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
        };
        
        // Вектор инициализации 64 бита (8 байт)
        std::vector<unsigned char> iv = {
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef
        };
        
        cipher.set_key(key);
        cipher.set_iv(iv);
        
        std::string original = "Hello, Magma!";
        std::vector<unsigned char> plaintext(original.begin(), original.end());
        
        // Шифрование
        auto ciphertext = cipher.encrypt(plaintext);
        
        // Вывод зашифрованных данных
        std::cout << "Ciphertext: ";
        for (auto byte : ciphertext) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        std::cout << std::endl;
        
        // Дешифрование
        auto decrypted = cipher.decrypt(ciphertext);
        std::string decrypted_str(decrypted.begin(), decrypted.end());
        
        std::cout << "Decrypted: " << decrypted_str << std::endl;
        
        // Проверка
        if (original == decrypted_str) {
            std::cout << "Encryption/Decryption successful!" << std::endl;
        } else {
            std::cout << "Error: decrypted text doesn't match original!" << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
