# COMP72070-Group3
Install Visual Studio
Install OpenSSL

Set Library Directories
Go to:
Project → Properties → VC++ Directories → Library Directories
C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD or MDd if debug
C:\OpenSSL-Win64\lib

Go to:
VC++ Directories → Include Directories
C:\Program Files\OpenSSL-Win64\include (locate your include)

Go to:

Linker → Input → Additional Dependencies
Add:
libssl.lib
libcrypto.lib
ws2_32.lib
crypt32.lib
