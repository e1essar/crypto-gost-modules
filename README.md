# CRYPTO-GOST VPN Prototype

Демонстрационный «VPN-канал» на основе обмена ClientHello/ServerHello и зашифрованных сообщений с алгоритмами Кузнечик и Магма (OpenSSL ENGINE).

## Зависимости

- CMake ≥ 3.10  
- Компилятор C++ (GCC/Clang) с поддержкой C++14  
- OpenSSL с поддержкой GOST-движка (`libssl`, `libcrypto`, engine-gost)

## Сборка

1. Создать каталог сборки и перейти в него:
   ```bash
   mkdir build && cd build
   ```

2. Скофигурировать проект:
   ```bash
   cmake ..
   ```

2. Скомпилировать:
   ```bash
   make
   ```

## Запуск демо

1. Запустите сервер (слушает порт 5555):
   ```bash
   ./server 5555
   ```

2. В отдельном терминале запустите клиент:
   ```bash
   ./client 127.0.0.1 5555
   ```
   
3. Клиент автоматически выполнит Handshake:
- ClientHello: HELLO:TLS1.3:1:KUZ:2:MAG
- ServerHello: SERVERHELLO:KUZ
- Тестовый зашифрованный обмен и подтверждение.

4. После этого откроется интерактивный чат:
- Вводите строки в клиенте → они шифруются и отправляются на сервер.
- Сервер печатает расшифровку и отвечает «Echo: …».
- Для выхода наберите exit.

## Тестирование
### Сервер
```
└─$ ./server 5555
Server listening on port 5555...
Client connected. Performing handshake...
Received ClientHello: HELLO:TLS1.3:1:KUZ:2:MAG
Sent ServerHello: SERVERHELLO:KUZ
Decrypted test message: `Hello from client`
Handshake complete. Secure channel established.
Entering secure message loop (type 'exit' to end):
[client] Hello!
[client] How are you?
[client] Bye!
```

### Клиент
```
└─$ ./client 127.0.0.1 5555
Sent ClientHello: HELLO:TLS1.3:1:KUZ:2:MAG
Received ServerHello: SERVERHELLO:KUZ
Decrypted ACK: `ACK from server`
Secure channel established. Type messages and press Enter (type 'exit' to quit):
Hello!
[server] Echo: Hello!
How are you?
[server] Echo: How are you?
Bye!
[server] Echo: Bye!
exit
```
