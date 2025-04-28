#include "kuznyechik.h"
#include <openssl/engine.h>
#include <stdexcept>

Kuznyechik::Kuznyechik() {
    // Загрузка движка GOST
    ENGINE* engine = ENGINE_by_id("gost");
    if (!engine) {
        throw std::runtime_error("Failed to load GOST engine");
    }
    
    if (!ENGINE_init(engine)) {
        ENGINE_free(engine);
        throw std::runtime_error("Failed to initialize GOST engine");
    }
    
    // Инициализация контекстов шифрования
    encrypt_ctx = EVP_CIPHER_CTX_new();
    decrypt_ctx = EVP_CIPHER_CTX_new();
    
    if (!encrypt_ctx || !decrypt_ctx) {
        ENGINE_finish(engine);
        ENGINE_free(engine);
        throw std::runtime_error("Failed to create cipher contexts");
    }
}

Kuznyechik::~Kuznyechik() {
    EVP_CIPHER_CTX_free(encrypt_ctx);
    EVP_CIPHER_CTX_free(decrypt_ctx);
}

void Kuznyechik::set_key(const std::vector<unsigned char>& key) {
    if (key.size() != 32) {
        throw std::invalid_argument("Key must be 32 bytes (256 bits)");
    }
    this->key = key;
}

void Kuznyechik::set_iv(const std::vector<unsigned char>& iv) {
    if (iv.size() != 16) {
        throw std::invalid_argument("IV must be 16 bytes (128 bits)");
    }
    this->iv = iv;
}

void Kuznyechik::init_encrypt() {
    const EVP_CIPHER* cipher = EVP_get_cipherbyname("kuznyechik-cbc");
    if (!cipher) {
        throw std::runtime_error("Kuznyechik cipher not found");
    }
    
    if (!EVP_EncryptInit_ex(encrypt_ctx, cipher, NULL, key.data(), iv.data())) {
        throw std::runtime_error("Encryption init failed");
    }
}

void Kuznyechik::init_decrypt() {
    const EVP_CIPHER* cipher = EVP_get_cipherbyname("kuznyechik-cbc");
    if (!cipher) {
        throw std::runtime_error("Kuznyechik cipher not found");
    }
    
    if (!EVP_DecryptInit_ex(decrypt_ctx, cipher, NULL, key.data(), iv.data())) {
        throw std::runtime_error("Decryption init failed");
    }
}

std::vector<unsigned char> Kuznyechik::encrypt(const std::vector<unsigned char>& plaintext) {
    init_encrypt();
    
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len;
    int ciphertext_len;
    
    if (!EVP_EncryptUpdate(encrypt_ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) {
        throw std::runtime_error("Encryption failed");
    }
    ciphertext_len = len;
    
    if (!EVP_EncryptFinal_ex(encrypt_ctx, ciphertext.data() + len, &len)) {
        throw std::runtime_error("Encryption finalization failed");
    }
    ciphertext_len += len;
    
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::vector<unsigned char> Kuznyechik::decrypt(const std::vector<unsigned char>& ciphertext) {
    init_decrypt();
    
    std::vector<unsigned char> plaintext(ciphertext.size());
    int len;
    int plaintext_len;
    
    if (!EVP_DecryptUpdate(decrypt_ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
        throw std::runtime_error("Decryption failed");
    }
    plaintext_len = len;
    
    if (!EVP_DecryptFinal_ex(decrypt_ctx, plaintext.data() + len, &len)) {
        throw std::runtime_error("Decryption finalization failed");
    }
    plaintext_len += len;
    
    plaintext.resize(plaintext_len);
    return plaintext;
}
