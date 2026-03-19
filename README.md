# COMP72070-Group3
Dependencies
C++17 compiler (MSVC or MinGW)

OpenSSL (for TLS)

Winsock2 (networking)




Build Instructions

Install OpenSSL and ensure headers and libs are accessible.

Compile the server:

g++ server.cpp -o server.exe -lssl -lcrypto -lws2_32

Compile the client:

g++ client.cpp -o client.exe -lssl -lcrypto -lws2_32

Ensure cert.pem and key.pem are in the same folder as server.exe.

