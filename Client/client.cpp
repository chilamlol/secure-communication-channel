#include <iostream>
#include <string>
#include<stdlib.h> // to use system() for writing terminal command line
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <fstream>

//gen PUPR keys
#include "./cryptopp/base64.h"
#include "./cryptopp/osrng.h" //AutoSeededRandomPool
#include "./cryptopp/rsa.h" //RSA Signature Schemes library
#include "./cryptopp/files.h" //file sink

//SHA1 hashing
#include "./cryptopp/sha.h" 
#include "./cryptopp/hex.h" //HexEncoder()

//SEED encryption library
#include "./cryptopp/seed.h"
#include "./cryptopp/filters.h"
#include "./cryptopp/modes.h"
#include "./cryptopp/secblock.h"


typedef unsigned char BYTE; //Declaring BYTE data type
using namespace std;

//save to file
void saveToFile (string message)
{
	ofstream myfile;
	string fileName;
	cout << "Please enter the file name you wish to save to: ";
	cin >> fileName;
	myfile.open(fileName.c_str());
	myfile << message;
	myfile.close();
	cout << "File is successfully saved." << endl;
}


//Read from file
string readFileMessage (string fileName)
{
    string message,line;
    ifstream infile;
    infile.open(fileName.c_str());
    if(!infile.is_open())
	return "Unable to open file";
    while(getline(infile,line))
    	message += line;
    infile.close();	
    return message;
}

//pump first 12 byte SEED key
void remakeSessionKey(string keyFile, string nonceFile)
{

	string key;
	string nonce;

	//store the key into a String
	CryptoPP::FileSource fs(keyFile.c_str(), false, new CryptoPP::StringSink(key));
	//Pump only the first 12 byte 
    	fs.Pump(24);

	//cout << "key: " << key << endl;
	//read the nonce from file
	nonce = readFileMessage(nonceFile.c_str());

	//cout << "nonce: " << nonce << endl;
	//12 byte of key + 4 byte of nonce
	key += nonce;
	//cout << "lastest key: " << key << endl;
	//Auto update the key
	CryptoPP::StringSource(key, true, new CryptoPP::FileSink(keyFile.c_str()));
}


//SEED encryption
string seedEncryption(string keyFile,string plain)
{
	CryptoPP::AutoSeededRandomPool prng;

	CryptoPP::SecByteBlock key(CryptoPP::SEED::DEFAULT_KEYLENGTH);
	CryptoPP::FileSource fs(keyFile.c_str(), true, new CryptoPP::ArraySink(key.begin(), key.size()));

	BYTE iv[CryptoPP::SEED::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	CryptoPP::CFB_Mode< CryptoPP::SEED >::Encryption e;
	e.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

	CryptoPP::FileSink file("seed.enc");

	CryptoPP::ArraySource as(iv, sizeof(iv), true,
		new CryptoPP::Redirector(file));
	
	CryptoPP::StringSource ss(plain, true,
		new CryptoPP::StreamTransformationFilter(e,
			new CryptoPP::Redirector(file)));
	
	//read file
	string message;
	CryptoPP::FileSource f1("seed.enc", true, new CryptoPP::HexEncoder(
	new CryptoPP::StringSink(message)));
	

	return message;
}

//SEED decryption
void seedDecryption(string keyFile, string msg)
{
	//IV is fixed at first 16 byte therefore first 16 byte
	cout << "IV: " << msg.substr(0,31) << endl;
	cout << "Ciphertext: " << msg.substr(32) << endl; //the rest is ciphertext

	CryptoPP::FileSink file("seed.enc");

	CryptoPP::StringSource ss(msg, true, new CryptoPP::HexDecoder (
			new CryptoPP::Redirector(file)));

	CryptoPP::AutoSeededRandomPool prng;

	CryptoPP::SecByteBlock key(CryptoPP::SEED::DEFAULT_KEYLENGTH);
	CryptoPP::FileSource f(keyFile.c_str(), true, new CryptoPP::ArraySink(key, key.size()));

	BYTE iv[CryptoPP::SEED::BLOCKSIZE];
	
	CryptoPP::FileSource fs("seed.enc", false);

	// Attach new filter
	CryptoPP::ArraySink as(iv, sizeof(iv));
	fs.Attach(new CryptoPP::Redirector(as));
	fs.Pump(CryptoPP::SEED::BLOCKSIZE); //Pump first 16 bytes

	CryptoPP::CFB_Mode< CryptoPP::SEED >::Decryption d;
	d.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

	CryptoPP::ByteQueue queue;
	fs.Detach(new CryptoPP::StreamTransformationFilter(d, new CryptoPP::Redirector(queue)));
	fs.PumpAll();

	string recovered;
	// The StreamTransformationFilter removes
    	//  padding as required.
    	CryptoPP::StringSink sink(recovered);
	queue.TransferTo(sink);

    	cout << "Plaintext: " << recovered << endl;

	if(recovered == "Ready")
	{	
		string kf, nf;
		cout << "Please eneter Session Key & Nonce file name: ";
		cin >> kf >> nf;
		remakeSessionKey(kf, nf);
		cout << "File is successfully updated." << endl;
	}
}

//Generate public and privte key
void keyGen(string prFileName, string puFileName, string dir)
{
    // InvertibleRSAFunction is used directly only because the private key
    // won't actually be used to perform any cryptographic operation;
    // otherwise, an appropriate typedef'ed type from rsa.h would have been used.
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::InvertibleRSAFunction privkey;
    privkey.Initialize(rng, 1024);

    // With the current version of Crypto++, MessageEnd() needs to be called
    // explicitly because Base64Encoder doesn't flush its buffer on destruction. 
    string pr = dir + "/" + prFileName;
    CryptoPP::Base64Encoder privkeysink(new CryptoPP::FileSink(pr.c_str()));
    privkey.DEREncode(privkeysink);
    privkeysink.MessageEnd();

    // Suppose we want to store the public key separately,
    // possibly because we will be sending the public key to a third party.
    CryptoPP::RSAFunction pubkey(privkey);
    string pu = dir + "/" + puFileName;
    CryptoPP::Base64Encoder pubkeysink(new CryptoPP::FileSink(pu.c_str()));
    pubkey.DEREncode(pubkeysink);
    pubkeysink.MessageEnd();

}

//generate random 4 byte nonce
void nonceGen(string nonceFileName)
{
    CryptoPP::SecByteBlock nonce(4);
    CryptoPP::AutoSeededRandomPool prng;

    prng.GenerateBlock(nonce, nonce.size());

    CryptoPP::StringSource(nonce, nonce.size(), true,
			new CryptoPP::HexEncoder(
				new CryptoPP::FileSink(nonceFileName.c_str())
		)
	);
    
}

//verifies 2 different file
bool verifyTwoFile (string file1, string file2)
{
    string message1, message2, line;
    ifstream infile;
    //read all data from file1
    infile.open(file1.c_str());
    if(!infile.is_open())
	return false;
    while(getline(infile,line))
    	message1 += line;
    infile.close();	

 //read all data from file2
    infile.open(file2.c_str());
    if(!infile.is_open())
	return false;
    while(getline(infile,line))
    	message2 += line;
    infile.close();

    int res = message1.compare(message2);
    if(res == 0)
       return true;
    else 
       return false;
}

//SHA1 hashing
void sha1Hash(string sha1File, string sha1Saved)
{
    CryptoPP::SHA1 sha1;
    string message, line;
    ifstream infile;
    infile.open(sha1File.c_str());
    if(!infile.is_open())
	exit(0);
    while(getline(infile,line))
    	message += line;
    infile.close();	

    CryptoPP::StringSource fs(message, true /* PumpAll */,
        new CryptoPP::HashFilter(sha1,
            new CryptoPP::HexEncoder(
                new CryptoPP::FileSink(sha1Saved.c_str()))));
}


//Encryption process
void decryption(string cipherFile, string keyFile, string savedFile)
{	
	//read file
	string cipher;
	CryptoPP::FileSource f1(cipherFile.c_str(), true, new CryptoPP::HexDecoder(
	new CryptoPP::StringSink(cipher)));

	// Pseudo Random Number Generator
    	CryptoPP::AutoSeededRandomPool rng;

    	//Read key which created earlier 
    	CryptoPP::ByteQueue bytes;
    	CryptoPP::FileSource file(keyFile.c_str(), true, new CryptoPP::Base64Decoder);
    	file.TransferTo(bytes);
    	bytes.MessageEnd();
    	CryptoPP::RSA::PrivateKey privateKey;
    	privateKey.Load(bytes);

	CryptoPP::RSAES_OAEP_SHA_Decryptor d( privateKey );

	CryptoPP::StringSource ss2( cipher, true,
    	new CryptoPP::PK_DecryptorFilter( rng, d,
        new CryptoPP::FileSink( savedFile.c_str() )
    ) // PK_EncryptorFilter
 ); // StringSource
}


//Client side
int main(int argc, char *argv[])
{
    cout << "\nWelcome client to use our program." << endl
	 << "Options: " << endl
	 << "keygen - generate a pair of private and public keys." << endl
	 << "connect - connect to the server." << endl
	 << "quit - exit the program." << endl << endl;
    string option;
    while(option != "connect" || option != "quit")
    {
    cout << ">";
    cin >> option;
    if(option == "keygen")
    {
	    cout << "Please enter the file name for private & public key & directory: ";
	    string prFileName, puFileName, dir;
	    cin >> prFileName >> puFileName >> dir;
	    keyGen(prFileName, puFileName, dir);
	    cout << "Private & Public key has been generated." << endl;
    }
    else if(option == "quit")
    {
	cout << "\nThank you for using the program." << endl;
	return 0;
    }
    else if(option == "connect")
    {
    //client requires to enter a client name
    string clientName;
    cout << "Please enter a client name(example: client_bob): ";
    cin >> clientName;
    //we need 2 things: ip address and port number, in that order
    if(argc != 3)
    {
        cerr << "Usage: ip_address port" << endl; exit(0); 
    } //grab the IP address and port number 
    char *serverIp = argv[1]; int port = atoi(argv[2]); 
    //create a message buffer 
    char msg[3000]; 
    //setup a socket and connection tools 
    struct hostent* host = gethostbyname(serverIp); 
    sockaddr_in sendSockAddr;   
    bzero((char*)&sendSockAddr, sizeof(sendSockAddr)); 
    sendSockAddr.sin_family = AF_INET; 
    sendSockAddr.sin_addr.s_addr = 
        inet_addr(inet_ntoa(*(struct in_addr*)*host->h_addr_list));
    sendSockAddr.sin_port = htons(port);
    int clientSd = socket(AF_INET, SOCK_STREAM, 0);
    //try to connect...
    int status = connect(clientSd,
                         (sockaddr*) &sendSockAddr, sizeof(sendSockAddr));
    if(status < 0)
    {
        cout<<"Error connecting to socket!"<<endl;
    }
    cout << clientName <<" connected to the server!" << endl;
    int bytesRead, bytesWritten = 0;
    struct timeval start1, end1;
    gettimeofday(&start1, NULL);

    string input, sesKey; //user input

    while(1)
    {
	while(input != "send" || input != "exit")
	{
		cout << ">";
		cin >> input;
		if(input == "exit")
			break;
		else if (input == "save")
		{
			saveToFile(msg);
		} 
		else if (input == "verify")
		{
			string f1,f2;
			cout << "Please enter the two file name to verify: ";
			cin >> f1 >> f2;
			if(verifyTwoFile(f1,f2))
			{
				cout << "Verification successful." << endl;
			} else
			{
				cout << "Error >> Verification failed." << endl;
			}
		}
		else if(input == "seed")
		{
			cout << "Key file: ";
			string keyFile;			
			cin >> keyFile;
			seedDecryption(keyFile, msg);
		}
		else if(input == "sha1")
		{
			cout << "Please enter the file name for hashing and file name to save in: ";
			string sha1File, sha1Saved;
			cin >> sha1File >> sha1Saved;
			sha1Hash(sha1File, sha1Saved);
			cout << "File is successfully hashed and saved!" << endl; 
		}
		else if(input == "decrypt")
		{
			string temp1, temp2, temp3;
			cout << "Please enter the cipher file, key file, and file to save in: ";
			cin >> temp1 >> temp2 >> temp3;
			decryption(temp1, temp2, temp3);
			cout << "Decryption process completed." << endl;
		}
		else if(input == "gennonce")
		{
			string nonceFile;
			cout << "Please enter the nonce file to save in: ";
			cin >> nonceFile;
			nonceGen(nonceFile);
			cout << "Nonce has been successfully generated" << endl;
		}		
		else if(input == "send")
		{
			cout << "Message: ";
			getline(cin >> ws, input);
			if(input == "attach")
			{
				cout << "File name you which to attach: ";
				cin >> input;
				input = readFileMessage(input);
			}
			if(input == "name")
			{
				input = clientName;
			}
			if(input == "seed")
			{
				string plain;
				cout << "Key file: ";
				cin >> sesKey;
				cout << "Plaintext: ";
				getline(cin >> ws, plain);
				input = seedEncryption(sesKey, plain); 
			}
			break;
		}
		else if(input == "help")
		{
			cout << "sha1, save, verify, genskey, decrypt, seed, gennonce, exit, send(attach, seed, name)" << endl;
		}
		else {
			cout << "Use 'help' for more information." << endl;
		}
	}
        memset(&msg, 0, sizeof(msg));//clear the buffer
        strcpy(msg, input.c_str());
        if(input == "exit")
        {
            send(clientSd, (char*)&msg, strlen(msg), 0);
            break;
        }
        bytesWritten += send(clientSd, (char*)&msg, strlen(msg), 0);
        cout << "Awaiting server response..." << endl;
        memset(&msg, 0, sizeof(msg));//clear the buffer
        bytesRead += recv(clientSd, (char*)&msg, sizeof(msg), 0);
        if(!strcmp(msg, "exit"))
        {
            cout << "Server has quit the session" << endl;
            break;
        }
        cout << "Server: " << msg << endl;
    }
    gettimeofday(&end1, NULL);
    close(clientSd);
    cout << "********Session********" << endl;
    cout << "Bytes written: " << bytesWritten << 
    " Bytes read: " << bytesRead << endl;
    cout << "Elapsed time: " << (end1.tv_sec- start1.tv_sec) 
      << " secs" << endl;
    cout << "Connection closed" << endl;
    return 0;   
}
else {
	cout << "Invalid option. Please try again." << endl;
}
}
}
