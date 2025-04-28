#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include "kuznyechik.h"
#include "magma.h"

static const std::vector<unsigned char> KEY = { /* same 32 bytes */
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
};
static const std::vector<unsigned char> IV = { /* same 16 bytes */
    0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
    0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port>\n";
        return 1;
    }
    const char* server_ip = argv[1];
    int port = std::stoi(argv[2]);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &serv.sin_addr);
    connect(sock, (sockaddr*)&serv, sizeof(serv));

    // 1) Send ClientHello
    std::string hello = "HELLO:TLS1.3:1:KUZ:2:MAG";
    write(sock, hello.data(), hello.size());
    std::cout << "Sent ClientHello: " << hello << "\n";

    // 2) Receive ServerHello
    char buf[256];
    int len = read(sock, buf, sizeof(buf));
    std::string sh(buf, len);
    std::cout << "Received ServerHello: " << sh << "\n";
    bool useKuz = (sh.find("KUZ") != std::string::npos);

    // 3) Init cipher
    Kuznyechik kuz;
    Magma mag;
    if (useKuz) {
        kuz.set_key(KEY);
        kuz.set_iv(IV);
    } else {
        mag.set_key(KEY);
        std::vector<unsigned char> iv8(IV.begin(), IV.begin()+8);
        mag.set_iv(iv8);
    }

    // 4) Send encrypted test
    std::string test = "Hello from client";
    std::vector<unsigned char> out;
    if (useKuz) out = kuz.encrypt(std::vector<unsigned char>(test.begin(), test.end()));
    else         out = mag.encrypt(std::vector<unsigned char>(test.begin(), test.end()));
    write(sock, out.data(), out.size());

    // 5) Receive encrypted ack
    len = read(sock, buf, sizeof(buf));
    std::vector<unsigned char> ctxt(buf, buf+len);
    std::vector<unsigned char> pt = useKuz ? kuz.decrypt(ctxt) : mag.decrypt(ctxt);
    std::string ack(pt.begin(), pt.end());
    std::cout << "Decrypted ACK: `" << ack << "`\n";

    std::cout << "Secure channel established. Type messages and press Enter (type 'exit' to quit):" << std::endl;
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "exit") break;
        // шифруем и отправляем
        auto out_ct = useKuz
            ? kuz.encrypt(std::vector<unsigned char>(line.begin(), line.end()))
            : mag.encrypt(std::vector<unsigned char>(line.begin(), line.end()));
        write(sock, out_ct.data(), out_ct.size());

        // читаем ответ
        int n = read(sock, buf, sizeof(buf));
        std::vector<unsigned char> resp_ct(buf, buf + n);
        auto resp_pt = useKuz ? kuz.decrypt(resp_ct) : mag.decrypt(resp_ct);
        std::string resp(resp_pt.begin(), resp_pt.end());
        std::cout << "[server] " << resp << std::endl;
    }

    close(sock);
    return 0;
}