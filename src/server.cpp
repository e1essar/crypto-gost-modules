#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include "kuznyechik.h"
#include "magma.h"

// Pre-shared key & IV (both sides must use the same)
static const std::vector<unsigned char> KEY = {
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
};
static const std::vector<unsigned char> IV = {
    0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
    0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <port>\n";
        return 1;
    }
    int port = std::stoi(argv[1]);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    bind(sock, (sockaddr*)&addr, sizeof(addr));
    listen(sock, 1);

    std::cout << "Server listening on port " << port << "...\n";
    int client = accept(sock, nullptr, nullptr);
    std::cout << "Client connected. Performing handshake...\n";

    // 1) Receive ClientHello
    char buf[256];
    int len = read(client, buf, sizeof(buf));
    std::string hello(buf, len);
    std::cout << "Received ClientHello: " << hello << "\n";

    // 2) Parse offered ciphers and pick one
    // Format: HELLO:TLS1.3:1:KUZ:2:MAG
    // We pick KUZ if offered, else MAG
    std::string chosen = "MAG";
    if (hello.find("KUZ") != std::string::npos)
        chosen = "KUZ";

    std::string server_hello = "SERVERHELLO:" + chosen;
    write(client, server_hello.data(), server_hello.size());
    std::cout << "Sent ServerHello: " << server_hello << "\n";

    // 3) Initialize cipher
    bool useKuz = (chosen == "KUZ");
    Kuznyechik kuz;
    Magma mag;
    if (useKuz) {
        kuz.set_key(KEY);
        kuz.set_iv(IV);
    } else {
        mag.set_key(KEY);
        // Magma uses 8-byte IV
        std::vector<unsigned char> iv8(IV.begin(), IV.begin()+8);
        mag.set_iv(iv8);
    }

    // 4) Receive encrypted test
    len = read(client, buf, sizeof(buf));
    std::vector<unsigned char> ciphertext(buf, buf+len);
    std::vector<unsigned char> plaintext;
    if (useKuz) plaintext = kuz.decrypt(ciphertext);
    else         plaintext = mag.decrypt(ciphertext);

    std::string test(plaintext.begin(), plaintext.end());
    std::cout << "Decrypted test message: `" << test << "`\n";

    // 5) Echo back encrypted ack
    std::string ack = "ACK from server";
    std::vector<unsigned char> out;
    if (useKuz) out = kuz.encrypt(std::vector<unsigned char>(ack.begin(), ack.end()));
    else         out = mag.encrypt(std::vector<unsigned char>(ack.begin(), ack.end()));
    write(client, out.data(), out.size());

    std::cout << "Handshake complete. Secure channel established.\n";
    std::cout << "Entering secure message loop (type 'exit' to end):" << std::endl;
    while (true) {
        int n = read(client, buf, sizeof(buf));
        if (n <= 0) break;
        std::vector<unsigned char> in_ct(buf, buf + n);
        auto in_pt = useKuz ? kuz.decrypt(in_ct) : mag.decrypt(in_ct);
        std::string msg(in_pt.begin(), in_pt.end());
        if (msg == "exit") break;
        std::cout << "[client] " << msg << std::endl;

        // отвечаем echo
        std::string reply = "Echo: " + msg;
        auto out_ct = useKuz
            ? kuz.encrypt(std::vector<unsigned char>(reply.begin(), reply.end()))
            : mag.encrypt(std::vector<unsigned char>(reply.begin(), reply.end()));
        write(client, out_ct.data(), out_ct.size());
    }
    close(client);
    close(sock);
    return 0;
}