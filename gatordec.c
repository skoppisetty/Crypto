/* Decrypts the data
can be run in two modes using -l or -d
Author: Suresh Koppisetty
CNT 5410 Network Security FALL 2014 Assignment 2
University of Florida
Date : 09/18/2014
Link : http://www.cise.ufl.edu/class/cnt5410fa14/hw/hw2.html
*/

#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define GCRYPT_VERSION "1.5.0"

#define SALT "NaCl" // given in the Assignment
#define PASSLENGTH 10 // Taking a default password length for malloc
#define KEYLENGTH_SHA 16 // AES keylength setting can be multiples of 16
#define ITER 4096 // Given in Assignment - Its used for the number of iterations for key gen using PBKDF2
#define HMAC_SIZE 64 // output size for the HMAC value of encrypted text
#define ENCRYPT_ALGO GCRY_CIPHER_AES128 // AES encryption algo
#define ENCRYPT_MODE GCRY_CIPHER_MODE_CBC // AES encryption mode - Cipher Block Chaining 
#define FRAME_LENGTH 256  // frame length for socket send

static int IV[16] = {5844}; //initializing IV vector for the AES encryption.
int mode; // Used to check which mode its running (local or daemon(i.e network))
char * port; // port for the server communication


char * filename; // output file name i.e .uf file 
char * encrypted_file = "temp.uf"; // temporary file to save encrypted date received from socket

void print_buf(char *buf,int length){
	// function to print the buffer (Mainly used to Debug the code)
	// prints the hex of a given buffer "buff" of length "length"
	int i;
	for(i = 0; i < length; i++){
		printf("%02X ",(unsigned char) buf[i]); // %20X is used to print only the last two characters
	}
	printf("\n");
}

void set_server(char * port){
	// setup server to run in a daemon listening to connections
	// socket handlers
	int listenfd;
    int connfd;

    // changing the port char to int
    int PORT = atoi(port);
    printf("%d\n", PORT );

    // socket address for server and client
    struct sockaddr_in serv_addr , client_addr;
    int addrlen = sizeof(client_addr);

    // creating a socket 
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if(listenfd < 0)
    {
        printf("\n Error : Could not create socket \n");
        exit(-1);
    }

    // These vars for file receive
    int bytesReceived = 0;
    char recvBuff[256];
    memset(recvBuff, '0', sizeof(recvBuff));
    // printf("Size: %lu\n", sizeof(recvBuff) );

    // Setting up the server properties 
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(PORT); // same port as received from the terminal
	
	// binding the socket to that particular port
	if(bind(listenfd, (struct sockaddr*)&serv_addr,sizeof(serv_addr)) == -1){
		printf("\n Error : Bind error \n");
		close(listenfd);
        exit(-1);
	}

	// Listening on the Socket for connections, 5 indicate the max simultaneous connections we can handle
    listen(listenfd, 5);

    // taking a file handler to write the content received from network to a file and exit as required
    FILE *f_out;
    // filename should be the same as arg1, using global var to set it
    f_out = fopen(encrypted_file, "w+b"); 
    if(f_out == NULL)
    {
        printf("Error opening file");
        error(-1);
        // added this check here so that it errors out before a inbound connection
    }

    // while 1 loop is used to wait for connections (ddaemon mode)
    // Not handling HMAC as of now.
    // need to write code for that
    printf("Waiting for connections.\n");
    while(1)
    {
    	// Accept the connection and give us a socket handler
    	connfd = accept(listenfd, (struct sockaddr*)&client_addr, &addrlen);
	    //Read on the socket handler continously by 256
	    printf("Inbound File.\n");
	    while((bytesReceived = read(connfd, recvBuff, 256)) > 0)
	    {
	        fwrite(recvBuff, 1,bytesReceived,f_out);
	        if(bytesReceived < 256)
		    {
		        printf("Received successfully \n");
		        close(connfd);
		        fclose(f_out);
		        return;
		    }
	    }
	    close(connfd);
    }
}

void checkargs(int argc,char *argv[]){
	// this is called in the start to check whether user is using it roperly or not.
	// checking the arguments are according to the standard.
	if(argc < 3){
		printf("check usage : gatordec <input file> [-d < port >][-l]\n");
  		exit(0);		
	}
	if((strcmp(argv[2], "-l") != 0) && (strcmp(argv[2], "-d") != 0)){
		printf("check usage : -l or -d as second arg\n");
		// limiting to take only -l or -d options
  		exit(-1);
	}
	if((strcmp(argv[2], "-d") == 0) && argc < 4){
		printf("check usage : -d should follow by port\n");
		// -d shoud always follow by the port to listen to
  		exit(0);		
	}
	if((strcmp(argv[2], "-d") == 0)){
		mode = 1; // mode for network is 1, used in encrypt function to determine what to do with the output 
		// This is for daemon mode i.e network mode 
		filename = argv[1] ;
		set_server(argv[3]); // setting up the server to listen to connections
	}
	else if((strcmp(argv[2], "-l") == 0)){
		mode = 0; // local mode is 0
		// copying the string(arg[1]) to filename by removing .uf in last
		filename = (char *)malloc(strlen(argv[1])-3);
		strncpy(filename,argv[1],(strlen(argv[1])-3));
		 // copying the string to filename by removing .uf in last
		// printf("%s\n",filename ); // debug 
		// exit(-1);
	}
}

void grcrypt_init(){
	// initializing grcypt library wihth secure memory
	if (!gcry_check_version (GCRYPT_VERSION))
	 {
	   printf("libgcrypt version mismatch\n");
	   exit(-1);
	 }
	gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
}

char * read_file(FILE* fp){
	char * file_contents;
	long int input_file_size;
	fseek(fp, 0, SEEK_END);
	input_file_size = ftell(fp);
	rewind(fp);
	file_contents = malloc(input_file_size * (sizeof(char)));
	fread(file_contents, sizeof(char), input_file_size, fp);
	return file_contents;
}

size_t get_filesize(FILE* fp){
	long int input_file_size;
	input_file_size = ftell(fp) + 1;
	return input_file_size;
}

void print_key(char *key){
	// printing the key generated by the password using PBKDF2
	// printing it as the example code shown in the assignment link
	int i;
	for(i = 0; i < KEYLENGTH_SHA; i++){
		printf("%02X ",(unsigned char) key[i]);
	}
	printf("\n"); // adding a break after key printing to match the standards as assignment
}

void get_key(char *pass, char *key){
	int i, error;
	/*
	pass - password entered by user
	GCRY_KDF_PBKDF2 - Algo for key gen
	GCRY_MD_SHA512 - SHA512 with ITER (i.e 4096) iterations
	we will get a key of KEYLENGTH_SHA
	SALT - globally defined (Best if its random)
	if any error occurs we get non zero return value for gcry_kdf_derive function
	*/
	error = gcry_kdf_derive(pass, strlen(pass), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, SALT, 
						strlen(SALT), ITER, KEYLENGTH_SHA, key);
	if(error != 0 ){
		// return non zero if error
		printf("\n Failed with error : %s\n", gcry_strerror(error));
	}
	else{
		printf("Key: ");
		print_key(key);
	}
}

char * get_hmac(char * cipher, char * key, size_t length){
	/* Generating hmac from the encrypted content
	GCRY_MD_SHA512 - Algo
	flags or of GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC 
	indicating that its secure mode and we need HMAC
	*/
	gcry_error_t err;
	gcry_md_hd_t hm;
	err = gcry_md_open(&hm, GCRY_MD_SHA512, GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
	if(err != GPG_ERR_NO_ERROR){
		printf ("Error at opening handle for hmac: %s\n",gcry_strerror(err));
		exit(-1);
	}
	err = gcry_md_enable(hm,GCRY_MD_SHA512);
	err = gcry_md_setkey(hm, key,KEYLENGTH_SHA );
	if(err != GPG_ERR_NO_ERROR){
		printf ("Error at setting key: %s\n",gcry_strerror(err));
		exit(-1);
	}
	// generating the HMAC using the cipher text
  	gcry_md_write(hm,cipher,length);
  	gcry_md_final(hm);
  	// printf("\nlength: %lu\n",length);

	char * hmac;
	hmac = gcry_md_read(hm , GCRY_MD_SHA512 );
	if(hmac == NULL ){
		printf ("hmac null ?\n");
		// exit(-1);
	}
	// print_buf(hmac,64); // debug
	// printf("hmac length : %lu\n",strlen(hmac)); // debug to check hmac length should be 64
	return hmac;
}

char * aes_decrypt(char *encBuffer,char * key,size_t txtLength,char *hmac){
	gcry_cipher_hd_t h;
	gcry_error_t err;
	int status_decrypt;
	char *hmac_gen;
	// printf("string length :%lu\n",txtLength);
	char * outBuffer = malloc(txtLength);
	// init output to be of same length as input

	// open cipher handle
	err = gcry_cipher_open(&h, ENCRYPT_ALGO, ENCRYPT_MODE, GCRY_CIPHER_SECURE);
	if(err != GPG_ERR_NO_ERROR){
		printf ("Error at open: %s\n",gcry_strerror(err));
		exit(-1);
	}
    // set the same key as encryption
    err = gcry_cipher_setkey(h, key, KEYLENGTH_SHA);
    if(err != GPG_ERR_NO_ERROR){
		printf ("Error at setting key: %s\n",gcry_strerror(err));
		exit(-1);
	}
	// set the same IV as encryption
    err = gcry_cipher_setiv(h, &IV, 16);
    if(err != GPG_ERR_NO_ERROR){
		printf ("Error at setting IV: %s\n",gcry_strerror(err));
		exit(-1);
	}	
	// decrypt the content
    status_decrypt = gcry_cipher_decrypt(h, outBuffer, txtLength, encBuffer, txtLength);
    if(status_decrypt != 0){
		printf ("Error at decrypting:%s %s\n",gcry_strerror(status_decrypt),gcry_strerror(status_decrypt));
	}

	hmac_gen = get_hmac(encBuffer,key,txtLength);
	// generate the hmac of the encrypted content at server
	// check with the extracted hmac from file or network

	int j;
	for(j=0;j<64;j++){
		if (hmac_gen[j] != hmac[j]){
			printf ("HMAC verification failed\n");
			exit(62);
		}
	}
	printf("HMAC Verified\n");

	FILE * f;
	
	if( access( filename, F_OK ) != -1 ) {
	   	printf ("File already present\n");
	    exit(33);
		// Check for file exists and exit with code 33
	} 
	f = fopen(filename,"w+b");
	// hardcoded file name change it - Done

	// Since we added trailing zeroes at original file to make length a proper multiple of 16
	// we get the same content after decryption but with the trailing zeroes
	// Since we dont need them i am checcking for the last non zero element in the last row and writing till there
	// print_buf(outBuffer,txtLength); // debug purposes
	if (f){
		fwrite(outBuffer, txtLength -16, 1, f);
		int index,j;
		char * last_row = (outBuffer + txtLength -16);
		for(j=16;j>0;j--){
			// printf("%d %02X\n",j-1, last_row[j - 1]);
			if(last_row[j-1] != 0){
				index = j;//last non zero element
				// printf("Last index is %d %02X\n",index,last_row[j-1]);
				j = -1;
			}
		}
		fwrite(outBuffer+(txtLength -16),index+1, 1, f);
		// ignoring last 0 chars when printing + 1 is for trainling char
		fclose(f);
	}
	else{
		printf ("Error at opening file to write\n");
		exit(33);
		// this can be moved further to save time.
	}
	return outBuffer;

}

void decrypt_file(char * encryp_filename, char * key){
	// this function takes the file as input and generates encrypted content buffer
	// and HMAC buffer and passes it to aes_decrypt function
	// aes_decrypt checks for HMAC authorization
	FILE *fh;
	fh=fopen(encryp_filename, "r");
		if (fh == NULL) {
	  		printf("Can't open input file.\n");
	  		exit(0);
		}
	char * file_contents, *hmac , *cipher;
	long int input_file_size;
	size_t input_length;
	
	fseek(fh, 0, SEEK_END);
	input_file_size = ftell(fh) - 1;
	//printf("Input %lu %lu\n",input_file_size , input_file_size%16 );
	// HMAC is always of 64, so allocating memory to it
	hmac = (char * ) malloc(64 * (sizeof(char)));
	// and the rest will be cipher text so allocating filesize - 64 to cipher
	cipher = (char * ) malloc((input_file_size - 64) * (sizeof(char)));
	// going to the last 65 lines (because i have added a trailing 0 in client) so 64 +1
	// read from there 64 chars to get the HMAC
	fseek (fh, -65L, SEEK_END);
	fread(hmac,sizeof(char),64,fh);
	
	// once u read that go to start and read encrypted content
	//that is of length filesize - 64
	rewind(fh);
	fseek (fh, 0, SEEK_SET);
	fread(cipher,sizeof(char),input_file_size-64,fh);
	

	// print_buf(hmac,64); // debug
	// print_buf(cipher,input_file_size-64); //debug
	aes_decrypt(cipher,key,input_file_size-64,hmac);
	// this function checks client vs generated HMAC  and also decrypts the file
}

void main(int argc, char *argv[]){
	// checking args and setting params
	checkargs(argc,argv);
	// init libgrcypt with secure memory
	grcrypt_init();

	char pass[PASSLENGTH],key[KEYLENGTH_SHA],*file_contents;
	FILE *fp;
	size_t input_length;

	// capturing password for password generation
	printf("Password: ");
	scanf("%s", pass);

	
	//generating the key
	get_key(pass,key);

	if(mode == 0){
		// only do this for local mode
		// for local mode
		decrypt_file(argv[1],key);
		printf("successfully decrypted the %s file to %s\n",argv[1],filename);	
	}
	if(mode == 1){
		// printf("Decrypting the %s file to %s\n",encrypted_file,filename);	
		decrypt_file(encrypted_file,key);
		printf("successfully received and decrypted\n");
		remove(encrypted_file);	
	}
}