# Secure Communication Channel with SEED Encryption

The .cpp file is created under linux/UNIX environment.

All the .txt, .dat files is not nercessery, only .cpp file is essential.

Note: Crypto++ 850 library is being used in this project
      Therefore, the cryptopp850 is needed for the compilation.

## Requirement

- .cpp file is required at home directory

- crypto++ library

- alice/bob directory

## Run with linux terminal

### Server

Compile
```
g++  server.cpp -o server cryptopp/libcryptopp.a
```
Run
```
./server [port number]
```

### Client

Compile
```
g++ client.cpp -o client cryptopp/libcryptopp.a
```
Run
```
./client [server ip adress] [port number]
```
<br />

Use 'help' for more command
