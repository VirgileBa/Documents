#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>

/* 
 * exemples du hmac(nist):   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA256.pdf
 * exemples du sha256(nist): https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
 * */

typedef unsigned char byte;



int main(){
    void sha256(long byte_l ,byte* msg,byte hash[32]);
    void hmacsha256(long byte_keylength, byte* key, long byte_msglength,byte* msg, byte hmac256result[32]);
    byte hash[32];
    byte hmac[32];
    
    
                  
    printf("\n\n\n------------------------------------------------------------------------------"); 
    printf("\nles exemples sont ceux de ces urls. ces urls sont au debut de ce .c prets a etre copies:\n");      
    printf("\nexemples du hmac(nist):   https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA256.pdf\n\nexemples du sha256(nist): https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf");
	printf("\n\n------------------------------------------------------------------------------");

    printf("\nSHA256 EXEMPLE:\n");

    //test vectors for sha256
    byte msg[3]={'a','b','c'};
    byte msg2[56]={'a','b','c','d','b','c','d','e','c','d','e','f','d','e','f','g','e','f','g','h','f','g','h','i','g','h','i','j','h','i',
                   'j','k','i','j','k','l','j','k','l','m','k','l','m','n','l','m','n','o','m','n','o','p','n','o','p','q'};

    //print the hash input
    printf("\nMESSAGE INPUT OF SHA 256:\n");
    for(int i=0; i<3;i++){
        if(i%4==0){printf(" ");}
        printf("%c",msg[i]);
		}    

	sha256(3,msg,hash);
 
    //print the hash result
    printf("\n\nSHA256 RESULT:\n");
    for(int i=0; i<32;i++){
        if(i%4==0){printf(" ");}
        printf("%02X",hash[i]);
		}

    //print the hash input
    printf("\n\n\nMESSAGE INPUT OF SHA 256:\n");
    for(int i=0; i<56;i++){
        if(i%4==0){printf(" ");}
        printf("%c",msg2[i]);
		}                   
                      
	sha256(56,msg2,hash);
 
    //print the hash result
    printf("\n\nSHA256 RESULT:\n");
    for(int i=0; i<32;i++){
        if(i%4==0){printf(" ");}
        printf("%02X",hash[i]);
		}
		
	printf("\n\n------------------------------------------------------------------------------");
    printf("\nHMAC EXEMPLE:\n");
//test vector for hmac
    byte text[34] = {'\x53', '\x61', '\x6D', '\x70', '\x6C', '\x65', '\x20', '\x6D', '\x65', '\x73', '\x73',
    '\x61', '\x67', '\x65', '\x20', '\x66', '\x6F', '\x72', '\x20', '\x6B', '\x65', '\x79', '\x6C', '\x65',
    '\x6E', '\x3D', '\x62', '\x6C', '\x6F', '\x63', '\x6B', '\x6C', '\x65', '\x6E'};
    
    byte key[64] = {'\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\x09', '\x0A',
                   '\x0B', '\x0C', '\x0D', '\x0E', '\x0F', '\x10', '\x11', '\x12', '\x13', '\x14', '\x15',
                   '\x16', '\x17', '\x18', '\x19', '\x1A', '\x1B', '\x1C', '\x1D', '\x1E', '\x1F', '\x20',
                   '\x21', '\x22', '\x23', '\x24', '\x25', '\x26', '\x27', '\x28', '\x29', '\x2A', '\x2B',
                   '\x2C', '\x2D', '\x2E', '\x2F', '\x30', '\x31', '\x32', '\x33', '\x34', '\x35', '\x36',
                   '\x37', '\x38', '\x39', '\x3A', '\x3B', '\x3C', '\x3D', '\x3E', '\x3F'};


	//print the input of hmac
    printf("\nHMAC TEXT:\n");
    for(int i=0; i<34;i++){
        if(i%4==0){printf(" ");}
        printf("%02X",text[i]);
    }

    //print the hmac key
    printf("\n\nHMAC KEY:\n");
    for(int i=0; i<64;i++){
        if(i%4==0){printf(" ");}
        printf("%02X",key[i]);
    }

    hmacsha256(64,key,34,text,hmac); 
          
    //print the hmac result
    printf("\n\nHMAC RESULT:\n");
    for(int i=0; i<32;i++){
        if(i%4==0){printf(" ");}
        printf("%02X",hmac[i]);        
    }
	printf("\n\n------------------------------------------------------------------------------\n\n\n");
}

 
void hmacsha256(long byte_keylength, byte* key, long byte_msglength,byte* msg, byte hmac256result[32]){
	//processing k0
	void sha256(long byte_l ,byte* msg,byte hash[32]);
	byte k0[64];
	if(byte_keylength>64){
		sha256(byte_keylength,key, k0);
		for(int i=32;i<64;i++){k0[i]=0;}
		}
	else{
		for(int i=byte_keylength;i<64;i++){k0[i]=0;}
		for(int i=0;i<byte_keylength;i++){k0[i]=key[i];}
		}
		
	//computing (ipad XOR k0) || M		
	byte ipadtext[64+byte_msglength];
	for(int i=0;i<64;i++){ipadtext[i]= '\x36' ^ k0[i];}
	for(int i=64;i<64+byte_msglength;i++){ipadtext[i]=msg[i-64];}
	byte hash1[32];

	/*printf("\nhipadtext: ");
    for(int i=0; i<64+byte_msglength;i++){
        if(i%4==0){printf(" ");}
        if(i==64){printf("//");}
        printf("%02X",ipadtext[i]);
    }*/
    
    //computing hash of it
	sha256(64+byte_msglength,ipadtext,hash1);

	/*printf("\nh1: ");
    for(int i=0; i<32;i++){
        if(i%4==0){printf(" ");}
        if(i==64){printf("//");}
        printf("%02X",hash1[i]);
    }*/

	//computing (opad XOR k0) || first hash
	byte entryhash2[96];
	for(int i=0;i<64;i++){
		entryhash2[i] = '\x5c' ^ k0[i];
		}
	for(int i=64;i<96;i++){
		entryhash2[i] = hash1[i-64];
		}
		
	/*printf("\nk0xor opad: ");
    for(int i=0; i<64;i++){
        if(i%4==0){printf(" ");}
        if(i==64){printf("//");}
        printf("%02X",entryhash2[i]);
    }*/		
	
	//computing it's hash and putting it in hmac256result	
	sha256(96,entryhash2,hmac256result);
	} 



//sha 256 avec (petite) restriction: les messages sont en octets, (nombre de bits total multiple de 8)    

void sha256(long byte_l ,byte* msg,byte hash[32]){
	//sizeof will return the size of the adress, hence why it's passed as argument,
	//see https://stackoverflow.com/questions/34216022/sizeof-function-not-working-in-function
	uint32_t ch(uint32_t a,uint32_t b,uint32_t c);	
	uint32_t maj(uint32_t a,uint32_t b,uint32_t c);
	uint32_t sum0(uint32_t a);
	uint32_t sum1(uint32_t a);
	uint32_t sigma0(uint32_t a);
	uint32_t sigma1(uint32_t a);
	
	//calculating the length of the padded message
	if(byte_l >= pow(2,61)){printf("message trop long!");exit(1);}
	int byte_k = (56 - (byte_l+1))%64;	// bit_k+1 = 448-bit_l [512] => (bit_k+1)/8 = 56 - byte_l => byte_k +1 = 56- byte_l  [64]
	if(byte_k<0){byte_k+=64;}			// => byte_k = 56- (byte_l+1)  [64]  avec byte_k le nmb de blocs de 8 bits egaux a 0
	long padded_byte_l = byte_l + byte_k + 9;	//+9: 8 pour coder bit_l et 1 bloc 0b10000000
	byte padded_msg[padded_byte_l];	

	//padding
	for(long i=0; i< byte_l;i++){ //first part is the message
		padded_msg[i] = msg[i];
		}
	padded_msg[byte_l] = '\x80'; //we append a 1 and then 7 0s straight away in the form of a byte 
								 //because we know 8|448, and our message was of length 8*l	
	for(long i = byte_l+1; i< padded_byte_l -8;i++ ){
		padded_msg[i]=0;
		}
	unsigned long long bit_l = 8*byte_l; //unsigned long long car un shift de plus de la taille du type de gauche
	for(long i=0;i<8;i++){				 //provoque des comportements non définit: (int) 24 >> 32 =24 par exemple
		padded_msg[padded_byte_l-1-i] = (bit_l>>(8*i))&255;
		} 

	//parsing
	if(padded_byte_l%64!=0){printf("erreur de longeur de padding!");exit(1);}
	long N = padded_byte_l / 64;
	uint32_t  parsed_msg[N][16]; //dans pared_msg[i][j]: block M^(i+1)_j
	for(long i =0;i<N;i++){
		for(int j =0;j<16;j++){
			parsed_msg[i][j] = padded_msg[64*i+4*j]*256*256*256 + padded_msg[64*i+4*j+1]*256*256
			+ padded_msg[64*i+4*j+2]*256 + padded_msg[64*i+4*j+3];}
		}

	uint32_t schedule[64];
	uint32_t H[8] = {0X6a09e667, 0Xbb67ae85, 0X3c6ef372, 0Xa54ff53a, 0X510e527f, 0X9b05688c, 0X1f83d9ab, 0X5be0cd19};
		
	uint32_t K[64] = {0X428a2f98, 0X71374491, 0Xb5c0fbcf, 0Xe9b5dba5, 0X3956c25b, 0X59f111f1, 0X923f82a4, 0Xab1c5ed5,
					0Xd807aa98, 0X12835b01, 0X243185be, 0X550c7dc3, 0X72be5d74, 0X80deb1fe, 0X9bdc06a7, 0Xc19bf174,
					0Xe49b69c1, 0Xefbe4786, 0X0fc19dc6, 0X240ca1cc, 0X2de92c6f, 0X4a7484aa, 0X5cb0a9dc, 0X76f988da,
					0X983e5152, 0Xa831c66d, 0Xb00327c8, 0Xbf597fc7, 0Xc6e00bf3, 0Xd5a79147, 0X06ca6351, 0X14292967,
					0X27b70a85, 0X2e1b2138, 0X4d2c6dfc, 0X53380d13, 0X650a7354, 0X766a0abb, 0X81c2c92e, 0X92722c85,
					0Xa2bfe8a1, 0Xa81a664b, 0Xc24b8b70, 0Xc76c51a3, 0Xd192e819, 0Xd6990624, 0Xf40e3585, 0X106aa070,
					0X19a4c116, 0X1e376c08, 0X2748774c, 0X34b0bcb5, 0X391c0cb3, 0X4ed8aa4a, 0X5b9cca4f, 0X682e6ff3,
					0X748f82ee, 0X78a5636f, 0X84c87814, 0X8cc70208, 0X90befffa, 0Xa4506ceb, 0Xbef9a3f7, 0Xc67178f2};
		
	uint32_t T1;
	uint32_t T2;
	uint32_t a,b,c,d,e,f,g,h;
	for(long t=0; t<N;t++){
		for(int i =0;i<64;i++){
			if(i<16){schedule[i]=parsed_msg[t][i];/*printf("\ni=%d:%08X",i,schedule[i])*/;}
			else{schedule[i]= sigma1(schedule[i-2]) + schedule[i-7]+ sigma0(schedule[i-15])+schedule[i-16];} //bien l'addi mod 2^32		
			}
		a=H[0]; b=H[1]; c=H[2];d=H[3]; e=H[4];f=H[5];g=H[6];h=H[7];
		for(int j=0;j<64;j++){
			T1= h + sum1(e) + ch(e,f,g) + K[j] + schedule[j];
			T2= sum0(a) + maj(a,b,c);
			h=g;
			g=f;
			f=e;
			e=d+T1;
			d=c;
			c=b;
			b=a;
			a=T1+T2;		//no collision, when a value is used, it is the old value still.
            //printf("\nj=%d: a=%08X b=%08X c=%08X d=%08X e=%08X f=%08X g=%08X h=%08X",j,a,b,c,d,e,f,g,h);
            //printf("\nj=%d: K[%d]=%X sum1(e)=%X ch(e,f,g)=%X W[i]=%X",j,j,K[j],sum1(e),ch(e,f,g),schedule[j]);
			}
			
		H[0]+=a; H[1]+=b; H[2]+=c; H[3]+=d;
		H[4]+=e; H[5]+=f; H[6]+=g; H[7]+=h;
		//for(int i=0;i<8;i++){printf("\nHash[%d]:%X ",i,H[i]);}
		}
	/*printf("\n results: ");*/
	for(int i=0; i<32;i++){
	   /* printf("%02X ", (H[i/4]>>(8*(3-(i%4))) &255) );*/
		hash[i] = H[i/4]>>(8*(3-(i%4))) &255; // 255=0b11111111
		}
	}


uint32_t ch(uint32_t a,uint32_t b,uint32_t c){
	return (a & b) ^ ((~a) & c);
	}

uint32_t maj(uint32_t a,uint32_t b,uint32_t c){
	return (a & b) ^ (a & c) ^ (b & c);
	}

uint32_t sum0(uint32_t a){
	return ((a >> 2)|(a << 30)) ^((a >> 13)|(a << 19)) ^((a >> 22)|(a << 10)); 
	}

uint32_t sum1(uint32_t a){
	return ((a >> 6)|(a << 26)) ^((a >> 11)|(a << 21)) ^((a >> 25)|(a << 7)); 
	}

uint32_t sigma0(uint32_t a){
	return ((a >> 7)|(a << 25)) ^ ((a >> 18)|(a << 14)) ^ (a>>3);
	}

uint32_t sigma1(uint32_t a){
	return  ((a >> 17)|(a << 15)) ^ ((a >> 19)|(a << 13)) ^ (a>>10);
	}
