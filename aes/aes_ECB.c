#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned char byte;


// argv[0]: a.out
// argv[1]: keyclength: 128, 192 ou 256
// argv[2]: cipher or decipher
// argv[3]: file to cipher
// argv[4]: file receiving the cipher

int main(int argc,char* argv[]){
	//exit and print an error if the second argument is neither cipher nor decipher
	if(strcmp(argv[2],"cipher")!=0 && strcmp(argv[2],"decipher")!=0){
		printf("enter 'cipher' or 'decipher' as 2nd argument!");
		exit(1);
		}

	//declarations
	void aes(int keylen,byte* key, byte data[16], byte out[16]);
	void aesdecipher(int keylen,byte* key,byte data[16], byte out[16]);
	int askkey(int keylen, byte* key);
	long datasize;			//the size of the file
	byte* input;			//will store the input read off the input file 
	byte* output;			//will store the output to write on the output file
	size_t readresult;		//will be =0 if the ask key function went well, 1 otherwise
	byte workingblock[16];			//the base working block of length 16 bytes for aes
	byte outputblock[16];			//the base output block of length 16 bytes for aes
	int keylen = atoi(argv[1]);		//transform the keylength in an int
	int bytekeylen = keylen/8;		//calculate the len in bytes, which will be used for the ask key function
	byte* key = (byte*) calloc(bytekeylen,1);				//allocate memory for the key
	int askkeyres = askkey(bytekeylen,key);					//asks the key to the users and stores it in key
	if(askkeyres!=0){printf("key input error!"); exit(1);}	//exit the programm if the key wasn't properly entered
	
	//opening the data file:
	FILE * datafile;
	datafile = fopen(argv[3],"rb");
	if(datafile==NULL){printf("opening file error, maybe you miswrote the name or forgot the extension."); exit(1);}
	
	//calculating length of the data file:
	fseek (datafile , 0 , SEEK_END);		//place the file pointer at the end of the file with offset 0
	datasize = ftell (datafile);			//give the current value of the pointer, here the end
	rewind (datafile);						//come back to the start of datafile
	int rest = datasize%16;					//calculate the numbers of bits in the last "block"
	int blocknumbs = datasize/16;			//calculate the number of 16-bytes blocks
	if(blocknumbs==0){printf("\nERROR: ECB with cipher stealing only work on files that are more than 16 bytes!"); exit(1);}

	//allocate memory to contain the file:
	input = (byte*) malloc (datasize);
	output = (byte*) malloc (datasize);
	if(input == NULL) {printf("memory error!"); exit (1);}
	if(output == NULL) {printf("memory error!"); exit (1);}
	
	//copy the file in the buffer:
	readresult = fread (input,1,datasize,datafile);
	if(readresult != datasize){printf("erreur de lecture"); exit (1);}
	fclose (datafile);
		
	//ciphering, if arg 2 is 'cipher'
	if(strcmp(argv[2],"cipher")==0){	
		printf("\nciphering\n....\n");
		//ECB cipher: applying aes to each 16-bytes blocks
		for(int i =0;i<blocknumbs; i++){
			for(int j=0;j<16;j++){workingblock[j]=input[16*i+j];}		// in the ith step, we cipher the ith block, hence the 16*ith+j
			aes(keylen, key, workingblock, outputblock);				//bytes for j in [0,15]
			for(int j=0;j<16;j++){output[16*i+j]=outputblock[j];}
			}
		//cipher stealing part(non 16-bytes-long block):
		if(rest!=0){
			for(int j=0;j<rest;j++){							//we copy the 'rest' first bits of the ciphered last full block to the last 'rest' bits
				output[16*blocknumbs+j] = outputblock[j];		// of the output (at this point indeed workingblock contains the ciphered last full block).
				workingblock[j] = input[16*blocknumbs+j];	//copying the last 'rest' bits of the input in the first part of the working block
				}
			for(int j=rest;j<16;j++){workingblock[j]=outputblock[j];}
			aes(keylen, key, workingblock, outputblock);
			for(int j=0;j<16;j++){output[16*(blocknumbs-1)+j]=outputblock[j];}		//pasting the ciphered "new block" into the last full block of the output
			}				
		}

	//deciphering if arg 2 is 'decipher'
	if(strcmp(argv[2],"decipher")==0){
		printf("\ndeciphering\n....\n");

		for(int i =0;i<blocknumbs; i++){ //normal ECB decipher on all the full blocks
			for(int j=0;j<16;j++){workingblock[j]=input[16*i+j];}
			aesdecipher(keylen, key, workingblock, outputblock);
			for(int j=0;j<16;j++){output[16*i+j]=outputblock[j];}
			}
		//cipher stealing part(non 16-bytes-long block):
		if(rest!=0){
			for(int j=0;j<rest;j++){
				output[16*blocknumbs+j] = outputblock[j]; //at this point outputblock contains the last part plaintext followed by the tail of the 2nd to last ciphered block
				workingblock[j] = input[16*blocknumbs+j]; //the last bits of the input is the head of the last full ciphered block
				}
			for(int j=rest;j<16;j++){workingblock[j]=outputblock[j];}
			aesdecipher(keylen, key, workingblock, outputblock);
			for(int j=0;j<16;j++){output[16*(blocknumbs-1)+j]=outputblock[j];} //pasting the deciphered block
			}			
		}
		
		//pasting the result in the result file:
		FILE *resultfile = fopen(argv[4], "wb");
		if(resultfile==NULL){printf("erreur d'ouverture du fichier de sortie"); exit(1);}
		fwrite(output,1,datasize,resultfile);
		fclose (resultfile);
	
		// terminate
		free(key);   
		free (input);
		free (output);
		
		printf("\nECB program successfully finished!\n");
}


//*---------------Fonctions utilisées dans l'ECB---------------*//

//asks the key to the users and stores it in key, will return 0 if the program went well, 1 otherwise
int askkey(int bytekeylen, byte* key){
    int len = bytekeylen * 3 + 1;		//len is the possible maximum length of user input, maximum 3 times the number of hexadecimal characters in a 'bytekeylength' key, the +1 is for the end of arrya sign
    char* s = calloc(len, 1); 		//memory is initialised at 0
    printf("enter the key, with or without space, lower or upper case \nexemple: a1b2c3d4 or A1 b2 c3 d4 or A1b 2c3d 4 \n");
    fgets (s, len, stdin);

	//counting the numbers of significant characters in the input and checking for non hexadecimal characters
    int compteur=0;
    for (int i = 0; i < len-1; i++){ 
        if(s[i]<48 && s[i]!=32 && s[i]!=0 && s[i]!=10 ){printf("non hexadecimal character 1!");exit(1);}		//self explanatory
        if(57<s[i] && s[i]<65){printf("non hexadecimal character 2!");return 1;}
        if(70<s[i] && s[i]<97){printf("non hexadecimal character 3!");return 1;}    
        if(102<s[i]){printf("non hexadecimal character 4!");return 1;}
        if(s[i]!=32 && s[i]!=10 && s[i]!=0){compteur+=1;}
        }
        if(compteur!=2*bytekeylen){printf("the key is not of proper length!");return 1;} //there is twice as much charachter as key lenght cause each byte is two hexadecimal characters

	//transformations to normalize the input        
    for (int i = 0; i < len; i++){
        if(s[i]==0){s[i] = 20;}		//20 used as a code to mean "ignore me in the input". doesn't collide with the hexa values ranging from 0 to 15
        if(s[i]==10){s[i] = 20;}	//0 is for the case where all the allowed memory wasn't used, 10 for spaces,32 for when the user presses enter
        if(s[i]==32){s[i] = 20;}
        if(47<s[i] && s[i]<58){s[i]-= 48;}		//transform the ascii number into the corresponding value in hexa
        if(64<s[i] && s[i]<71){s[i]-= 55;}		//transform the ascii uppercase letter into the correspônding value in hexa
        if(96<s[i] && s[i]<103){s[i]-= 87;}		//transform the ascii lowercase letter into the correspônding value in hexa   
        }
        
    
    //actual transformation of two character blocks from their value to hexadecimal
    int pwr = 16;
    int j=0;
    for (int i = 0; i < len; i++){		//every time a value is encountered, either it's 20 and ignored either
        if(s[i]!=20){					//it'll send the value. if it's the first of a "block" (for exemple a is first in "a1")
            key[j] += s[i]*pwr;			//it'll multiply it by 16 otherwise, just adds the value (for exemple: the value of "a1" = value of "a"*16 + value of "1")
            if(pwr == 16){pwr=1;}		
            else{pwr=16;j++;}			//the counter j of key[j] is only incremented after encountering two valid values, aka a block 
            }							//that way we ensure we completely fill the key, no more no less.
        }
        
    printf ("the key : [");
    for (int i = 0; i < bytekeylen-1; i++){printf ("%02X,", key[i]);}
    printf ("%02X]\n", key[bytekeylen-1]);
    //terminate
    free(s);  
    return 0;
	}
