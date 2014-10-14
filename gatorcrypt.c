/* Encrypts the input file
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
char * filename; // output file name i.e .uf file
char * ip; // ip addrress of the server
char * port; // port for the server communication


void set_addr(char * addr){
	// setting ip address and port to a global variable
	// printf("%s\n",addr);
	// Since there is no chomp in C using strtok to chomping the address to ip and port
	ip = strtok(addr,":");
	port = strtok(NULL, ":");
}

void print_buf(char *buf,int length){
	// function to print the buffer (Mainly used to Debug the code)
	// prints the hex of a given buffer "buff" of length "length"
	int i;
	for(i = 0; i < length; i++){
		printf("%02X ",(unsigned char) buf[i]); // %20X is used to print only the last two characters
	}
	printf("\n");
}

void network_send(){
	/* This function is used for the daemon part of the assignment , it is used to send the file
	 to server */
	
	// Setting up the client to connect to server
	int sockfd; // socket handler 
	struct sockaddr_in serv_addr; // server address 

	// Open the socket handler to use it to connect to server
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0))< 0)
    {	
    	//checking for errors in Init
        printf("Error : Could not create socket (Check whether you have added all libraries) \n");
        exit(-1);
    }

    // Used global variable for ip and port to make it easy to call them from any function
    int PORT = atoi(port); // casting the global variable char to int

    /* Initialize server properties by using ip and port from the args */
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT); // port convertion from host byte order to network byte order.
    serv_addr.sin_addr.s_addr = inet_addr(ip); // easy way to convert it to a valid format
	

	// Connect to the socket using the handler
	if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))<0)
	    {
	        // happens when it fails to connect to the server.
	        printf("\n Error in establishing connection to Server\n");
	        exit(-1);
	        // configure the exit parameters to whatever code we want in future.
	    }

	// Socket Init is Done
	   FILE *fp = fopen(filename,"rb");
	   if(fp==NULL)
	   {
	       printf("encrypted file open error");
	       exit(-1);   
	   }   
	printf("Transmitting to %s:%s\n",ip,port);
	while(1){
        /* First read file in chunks of 256 bytes */
        unsigned char buff[256]={0};
         int nread = fread(buff,1,256,fp);
        // printf("Bytes read %d \n", nread);        

        /* If read was success, send data. */
        if(nread > 0)
        {
            write(sockfd, buff, nread);
        }

        if (nread < 256){break;} // final line of data
    }
    printf("Successfully sent the file\n");
}

void checkargs(int argc,char *argv[]){
	// this is called in the start to check whether user is using it roperly or not.
	// checking the arguments are according to the standard.
	if(argc < 3){
		printf("check usage : gatorcrypt <input file> [-d < IP-addr:port >][-l]\n");
  		exit(-1);		
	}
	if((strcmp(argv[2], "-l") != 0) && (strcmp(argv[2], "-d") != 0)){
		printf("check usage : -l or -d as second arg\n");
		// limiting to take only -l or -d options
  		exit(-1);
	}
	if((strcmp(argv[2], "-d") == 0) && argc < 4){
		printf("check usage : -d should follow by ip and port\n");
		// -d shoud always follow by the server info (ip and port)
  		exit(-1);		
	}
	if((strcmp(argv[2], "-d") == 0)){
		mode = 1; // mode for network is 1, used in encrypt function to determine what to do with the output 
		// This is for daemon mode i.e network mode 
		set_addr(argv[3]); // setting server properties globally
		filename = (char *)malloc(strlen(argv[1])+3);
		 // setting memory to do a strcat used 3 because of the three characters we are adding ".uf"
		strcat(filename,argv[1] );
		strcat(filename,".uf" );
		// saving to fine in both modes
		// printf("%s\n",filename ); // debug 
	}
	else if((strcmp(argv[2], "-l") == 0)){
		mode = 0; // local mode is 0
		filename = (char *)malloc(strlen(argv[1])+3);
		 // setting memory to do a strcat used 3 because of the three characters we are adding ".uf"
		strcat(filename,argv[1] );
		strcat(filename,".uf" );
		// printf("%s\n",filename ); // debug 
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

void save_file(char * buff,char * hmac,size_t txtLength){
	FILE * f;
	if( access( filename, F_OK ) != -1 ) {
	   	printf ("File already present\n");
	    exit(33);
		// Check for file exists and exit with code 33
	} 
		f = fopen(filename,"wb");
		if (f){
		// buff is encrypted content and hmac is HMAC generated
		fwrite(buff, txtLength, sizeof(char), f);
		fwrite(hmac, HMAC_SIZE +1 , sizeof(char), f);
		// added + 1 for the trailing char. just to finish the writing to file properly
		// basically writes a null value to the end.
		// output is equal to encrypted content length + HMAC length.
		fclose(f);
	}
	else{
		printf ("Error at opening file to write\n");
		exit(-1);
	}
}

char * aes_encrypt(char * txtBuffer,char * key,size_t txtLength){
	gcry_cipher_hd_t handle;
	gcry_error_t err;
	int status_encrypt;
	char *hmac;
    char * encBuffer;
    encBuffer = (char *) malloc(txtLength); // output to be of same length of input
	//	checking keylength and IV sizes of corresponding algo
	// size_t keyLength = gcry_cipher_get_algo_keylen(ENCRYPT_ALGO);
    // size_t blkLength = gcry_cipher_get_algo_blklen(ENCRYPT_ALGO);
	// printf("%lu  %lu\n",keyLength,blkLength);

    // opening handle for encryption
	err = gcry_cipher_open(&handle, ENCRYPT_ALGO, ENCRYPT_MODE, GCRY_CIPHER_SECURE);
	if(err != GPG_ERR_NO_ERROR){
		printf ("Error at open: %s\n",gcry_strerror(err));
		exit(-1);
	}

	// Setting the key
    err = gcry_cipher_setkey(handle, key, KEYLENGTH_SHA);
    if(err != GPG_ERR_NO_ERROR){
		printf ("Error at setting key: %s\n",gcry_strerror(err));
		exit(-1);
	}

	// Setting the IV
    err = gcry_cipher_setiv(handle, &IV, KEYLENGTH_SHA);
    if(err != GPG_ERR_NO_ERROR){
		printf ("Error at setting IV: %s\n",gcry_strerror(err));
		exit(-1);
	}

	// Encryption
    status_encrypt = gcry_cipher_encrypt(handle, encBuffer, txtLength, txtBuffer, txtLength);
    if(status_encrypt != 0){
		printf ("Error at encrypting:%s %s\n",gcry_strerror(status_encrypt),gcry_strerror(status_encrypt));
		exit(-1);
	}

	// generating the hmac of the encrypted output to write it to a file
	hmac = get_hmac(encBuffer,key, txtLength);

	// first writing the encrypted to a file
	save_file(encBuffer,hmac,txtLength);
	printf("Successfully encrypted the inputfile to %s\n",filename);

  //  	if(mode == 0){
  //  		// Local mode , just writing the encrypted value along with hash to file
		// save_file(encBuffer,hmac,txtLength);
		// printf("Successfully encrypted the inputfile to %s\n",filename);
  //  	}
   	if(mode == 1){
   		// Network mode
   		// Sending the encrypted content to network location
   		// initially was not saving the encrypted file and directly sending the buffer
   		// network_send(encBuffer, txtLength);
   		// changed it to save a temp file and send it
   		network_send();
   	}

    return encBuffer;

}


void main(int argc, char *argv[]){
	
	// checking the usage
	checkargs(argc,argv);

	// init of libgcrypto libs
	grcrypt_init();
	// init of variables for storing password ,key input file read and encrypted values respectively
	char pass[PASSLENGTH],key[KEYLENGTH_SHA], * file_contents, * cipher;
	FILE *fp;
	size_t input_length;

	// Capture the user input for key generation
	// pass has max length of PASSLENGTH
	printf("Password: ");
	scanf("%s", pass);

	fp=fopen(argv[1], "rb"); // here argv[1] is inputfile which we have to encrypt and send
	if (fp == NULL) {
  		printf("Can't open input file.\n");
  		exit(-1);
	}
	//generating the key using the captured password
	get_key(pass,key);

	// getting the input filesize
	fseek(fp, 0, SEEK_END);
	input_length = ftell(fp) - 1;

	// This is for files which dont have input_length in multiples of 16
	// i am adding traing zeroes to make it of a proper length
	// invalid length error occurs if its not of proper length because
	size_t new_size;
	if(input_length % KEYLENGTH_SHA == 0){
		 new_size = input_length;
		 // multiple of keylength
	}
	else{
		if(input_length < KEYLENGTH_SHA){
			new_size = KEYLENGTH_SHA;
			// if input length is less than keylength change the length to keylength 
			// rest values are 0 by default
		}
		else{
			new_size = (input_length/KEYLENGTH_SHA)*KEYLENGTH_SHA + KEYLENGTH_SHA ;
			// (input_length/KEYLENGTH_SHA)*KEYLENGTH_SHA is to take till the multiple part ignoring the last characters
			// Since we are ignoring them we are adding a KEYLENGTH_SHA to make it a perfect multiple of keylength
		}
	}
	// setting up memory for file read
	file_contents = (char *)malloc(new_size*sizeof(char));
	fseek(fp, 0, SEEK_SET);
	// reading from start
	fread(file_contents, sizeof(char), new_size, fp);
	// reading the whole file if the new_size is more than the actual file size you get 0.
	// this basically adds trailing 0 to make it a perfect multiple of keylemngth

	// Now after fixing the length issue
	// send the file contents to encrypt
	// aes_encrypt returns encrypted content
	cipher = aes_encrypt(file_contents,key,new_size);


}