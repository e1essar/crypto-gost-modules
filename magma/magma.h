#ifndef MAGMA_H
#define MAGMA_H

#include <openssl/evp.h>
#include <string>
#include <vector>

class Magma {
public:
    Magma();
    ~Magma();
    
    void set_key(const std::vector<unsigned char>& key);
    void set_iv(const std::vector<unsigned char>& iv);
    
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext);
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext);

private:
    EVP_CIPHER_CTX* encrypt_ctx;
    EVP_CIPHER_CTX* decrypt_ctx;
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;
    
    void init_encrypt();
    void init_decrypt();
};

#endif // MAGMA_H
