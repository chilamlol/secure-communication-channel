# Secure Communication Channel with SEED Encryption

The .cpp file is created under linux/UNIX environment.

All the .txt, .dat files is not nercessery, only .cpp file is essential.

Note: Crypto++ 850 library is being used in this project
      Therefore, the cryptopp850 is needed for the compilation.

Requirement:
.cpp file is required at home directory
cryptopp library
alice/bob directory

How to run:
Terminal command-
Server: g++  server.cpp -o server cryptopp/libcryptopp.a
	./server [port number]

Client: g++ client.cpp -o client cryptopp/libcryptopp.a
	./client [server ip adress] [port number]

Example run:
Server: g++  server.cpp -o server
	./server 54000

Output(server): Waiting for a client to connect....
       
Client: g++ client.cpp -o client
	./client 10.0.2.4 54000

Output(client): Connected to the server

Output(server): Connected with client!
		Awaiting client response...

Use 'help' for more command