#include <stdio.h>
#include <stdlib.h>
//on utilisera les unsigned char pour representer les octets
typedef unsigned char byte;

/*-----AES-----*/
//input: an int, the length of the key, a byte array, the key, an input block 'data' and a memory block to output 'out'.
//output: none, in place change of 'out' 
void aes(int keylen,byte* key,byte data[16], byte out[16]){
	//declarations
	void keyexp(int Nb,int Nr, int Nk, byte key[4*Nk],byte expkey[4][Nb*(Nr+1)]);				//expands the key
	void addroundkey(int Nb, int Nr, byte state[4][Nb], byte expkey[4][Nb*(Nr+1)],int rnd);		//same functions as the nist recommendation paper
	byte bytemult(byte a,byte b);
	void subbytes(int Nb, byte state[][Nb]);
	void shiftrows(int Nb, byte state[4][Nb]);
	void mixcolumns(int Nb, byte state[4][Nb]);
	byte bits2char(int bits[]);			//it will come in handy to change bytes in their bit array and the other way around
	int* char2bits(byte c,int *bits);
	int Nr; 		//same values as the nist recommendation paper
	int Nk;
	if(keylen==128){Nr=10; Nk=4;}
	else if(keylen==192){Nr=12; Nk=6;}
	else if(keylen==256){Nr=14; Nk=8;}
	else{printf("wrong key size"); exit(1);}
	int Nb = 4; /*idk why*/
	//expansion of the key
	byte expandedkey[4][Nb*(Nr+1)];
	keyexp(Nb,Nr,Nk,key,expandedkey);
	//initialization of the state as a 2d array of bytes
	byte state[4][Nb];
	for(int i=0; i<4;i++){
		for(int j=0;j<Nb;j++){
			state[i][j]=data[4*j+i];
			}
		}
	
	//cipher
	addroundkey(Nb,Nr,state,expandedkey,0);
	for(int i=1;i<Nr;i++){
		subbytes(Nb,state);
		shiftrows(Nb,state);
		mixcolumns(Nb,state);
		addroundkey(Nb,Nr,state,expandedkey,i);
		}
	subbytes(Nb,state);
	shiftrows(Nb,state);
	addroundkey(Nb,Nr,state,expandedkey,Nr);
	
	//outputing the state in the output memory
	for(int i=0; i<4;i++){
		for(int j=0;j<Nb;j++){
			out[4*j+i] = state[i][j];
			}
		}
}


//*---------------Fonctions utilisées dans l'aes---------------*//


/*-----multiplication de c par x dans GF(2^8)-----*/
//input: a byte 'c' coding a polynomial in GF(2^8) = GF(2)[X]/ < m(X)= x^8 + x^4 + x^3 + x +1> 
//output: a byte equal to c*X 
//purpose: used for the Sbox

byte xtime(byte c){
	if(c>=128){c = c<<1; c = c^27;}			//27 codes the m(X) of the quotient hence the XOR 27.
	else{c = c<<1;}
	return c;
	}


/*-----multiplication de polynomes-----*/
//input:  2 bytes, 'a' and 'b'
//output: a byte 'res' equal to a*b in GF(2^8)
//purpose: used in Sbox

byte bytemult(byte a,byte b){
	int* char2bits(byte c,int *bits);
	byte xtime(byte c);
	byte buffer;
	int bitsb[8];			 
	char2bits(b,bitsb);		//we will use the bits of b
	byte res = 0;			
	for(int i=0;i<8;i++){	//straightforward, a multiplied by b is SUM(a* bi*X^i) with bi coefficients of b
		if(bitsb[i]==1){	//where the coefficients bi are the bits b, hence a*bi = a (if bi=1) or 0 (if bi=0)
			buffer = a;		//and the addition is the XOR
			for(int j=0;j<i;j++){buffer = xtime(buffer);}
			res=res^buffer;
			}
		}
	return res;
	}
	

/*-----Sbox-----*/
//input: a byte 'a'
//output: a byte 'res' = Sbox(a)
//purpose: used in aes

byte sbox(byte a){
	byte bits2char(int bits[]);
	int* char2bits(byte c,int *bits);
	byte bytemult(byte a, byte b);
	int bitsc[8];
	char2bits(99,bitsc);			//99 corresponds to the c of the nist specification
	
	if(a==0){return 99;}
	else{
		byte inv = 0;
		while(bytemult(a,inv)!=1){			//calculate the inverse of a thanks to bytemult through an exhaustive research
			inv+=1;
			if(inv==256){printf("inverse non trouvé pour la Sbox!");return 0;}
			}

	    int bitsinv[8];
	    int bitsres[8];
	    char2bits(inv,bitsinv);			//accesses the bits of the inverse
	    
	    for(int i=0; i<8;i++){			//applying the needed XORs to the bits
			bitsres[i]= bitsinv[i] ^ bitsinv[(i+4)%8] ^ bitsinv[(i+5)%8] ^ bitsinv[(i+6)%8] ^ bitsinv[(i+7)%8] ^ bitsc[i];	
			}
		byte res = bits2char(bitsres);
		return res;
    	}
    }
    

/*-----subword-----*/
//input: a byte array 'word'
//output: none, in-place change of the array 'word'
//purpose: used in the key expansion

void subword(byte word[4]){
	byte sbox(byte a);
	for(int i=0; i<4;i++){			//straightforward, applies the Sbox to each byte of the word
		word[i]=sbox(word[i]);
		}
	}
	

/*-----subbytes-----*/
//input: an int 'Nb' and a 2d array 'state
//output: none, in-place change of the array 'state'
//purpose: used in aes

void subbytes(int Nb, byte state[][Nb]){
	byte sbox(byte a);
	for(int i=0; i<4;i++){
		for(int j=0; j<Nb;j++){			//straightforward, applies the Sbox to each byte of the state
			state[i][j]=sbox(state[i][j]);
			}
		}
	}


/*-----mixcolumns-----*/
//input: an int Nb and a 2d array 'state'
//output: none, in-place change of the array 'expkey'
//purpose: used in aes

void mixcolumns(int Nb, byte state[4][Nb]){
	byte bytemult(byte a, byte b);
	byte buffer[4];		//the buffer is here to store the values that are overwritten
	for(int j=0;j<Nb;j++){
		for(int i=0;i<4;i++){buffer[i]= state[i][j];}			//straightforward, applies the XORs specified in the nist specification paper
		state[0][j] = bytemult(buffer[0],2) ^ bytemult(buffer[1],3) ^ buffer[2] ^ buffer[3];
		state[1][j] = buffer[0] ^ bytemult(buffer[1],2) ^ bytemult(buffer[2],3) ^ buffer[3];
		state[2][j] = buffer[0] ^ buffer[1] ^ bytemult(buffer[2],2) ^ bytemult(buffer[3],3);
		state[3][j] = bytemult(buffer[0],3) ^ buffer[1] ^ buffer[2] ^ bytemult(buffer[3],2);
			}
	}


/*-----addroundkey-----*/
//input: three ints 'Nb' 'Nr'and 'rnd', two 2d byte array 'state' and 'expkey' 
//output: none, in-place change of the array 'expkey'
//purpose: used in aes

void addroundkey(int Nb, int Nr, byte state[4][Nb],byte expkey[4][Nb*(Nr+1)],int rnd){
	for(int j=0;j<Nb;j++){
		for(int i=0;i<4;i++){
			state[i][j]= state[i][j] ^ expkey[i][rnd*Nb+j]; //rnd*Nb ensure we consider the rnd'th block of Nb words that we indeed XOR with the state
			}
		}
	}


/*-----shiftrows-----*/
//input: an int 'Nb' and a byte 2d array 'state'
//output: none, in-place change of the array 'state'
//purpose: used in aes

void shiftrows(int Nb, byte state[4][Nb]){
	byte buffer[3];			//the buffers are here to preserve the first bytes that'll be overwritten
	buffer[0]=state[1][0];
	state[1][0]=state[1][1];
	state[1][1]=state[1][2];
	state[1][2]=state[1][3];
	state[1][3]=buffer[0];
	
	buffer[0]=state[2][0];
	buffer[1]=state[2][1];
	state[2][0]=state[2][2];
	state[2][1]=state[2][3];
	state[2][2]=buffer[0];
	state[2][3]=buffer[1];

	buffer[0]=state[3][0];
	buffer[1]=state[3][1];
	buffer[2]=state[3][2];
	state[3][0]=state[3][3];
	state[3][1]=buffer[0];
	state[3][2]=buffer[1];
	state[3][3]=buffer[2];
	}


/*-----keyexp-----*/
//input:	-3 integers 'Nb' 'Nr' 'Nk' espectively the number of columns of the state, the total number of rounds and
//			   the number of 4 byte words in the key 
//			-an array of bytes 'key' which is the cipher key
//			-an array of bytes 'expkey' which will receive the expanded key
//output: none, in-place change of the array 'expkey'
//purpose: gives the expanded key corresponding to the key for the aes.


void keyexp(int Nb,int Nr, int Nk, byte key[4*Nk],byte expkey[4][Nb*(Nr+1)]){
	byte xtime(byte c);
	byte* rot(byte word[4]);
	void subword(byte word[4]);
	byte temp[4];
	byte Rcon;

	for(int i=0;i<Nk;i++){
		expkey[0][i] = key[4*i];			//first nk words of the expanded key is the key	
		expkey[1][i] = key[4*i +1];
		expkey[2][i] = key[4*i +2];
		expkey[3][i] = key[4*i +3];
		}
		
	for(int i=Nk;i<Nb*(Nr+1);i++){
		temp[0] = expkey[0][i-1];			//some functions used on w[i-1] are implemented in-place so a temporary replacement for w[i-1] is needed
		temp[1] = expkey[1][i-1];
		temp[2] = expkey[2][i-1];
		temp[3] = expkey[3][i-1];
		if(i%Nk==0){
			Rcon = 1;			//Rcon here is the first byte of Rcon[i/Nk] in the nist paper
			int p = i/Nk -1;
			for (int j=0; j<p;j++){Rcon = xtime(Rcon);}
			rot(temp);
			subword(temp);
			temp[0] = temp[0] ^ Rcon;
			}
		else if(Nk>6 && i%Nk==4){subword(temp);}
		expkey[0][i] = expkey[0][i-Nk] ^ temp[0];
		expkey[1][i] = expkey[1][i-Nk] ^ temp[1];
		expkey[2][i] = expkey[2][i-Nk] ^ temp[2];
		expkey[3][i] = expkey[3][i-Nk] ^ temp[3];
		}
	}
	

/*-----rot-----*/
//input: an array of bytes 'word' 
//output:none, in-place change of the array 'word'
//purpose: used in key expansion, rotation of 1 to the left of 'word'

byte* rot(byte word[4]){
	byte buffer = word[0];
	word[0] = word[1];
	word[1] = word[2];
	word[2] = word[3];
	word[3] = buffer;
	return word;			//permet de faire printf(rot(word)) mais a eviter
	}
	
	
/*-----bits2char-----*/
//input: an array of ints containing 0s and 1s
//output: a byte 'c'
//purpose: gives the byte corresponding to the int array

byte bits2char(int bits[]){
	byte c = 0;
    int expo = 1;
    for (int i = 0 ; i != 8 ; i++){
		c += bits[i]*expo;
		expo=expo*2;
		}
    return c; 
	}


/*-----char2bits-----*/
//input: a byte 'c' (coded on 8 bits) and an array of ints 'bits'
//output: "none", in place change of the array 'bits'
//purpose: gives the bits of a byte as an array of ints with bits[0] = least significant (bits[0]=1 si c = 1)

int* char2bits(byte c,int *bits){
    for (int i = 0 ; i != 8 ; i++){
        bits[i] = (c >> i) & 1;
		}
	return bits;			//permet de faire g(f()) mais a eviter
	}


/*-----decipherAES-----*/
//
void aesdecipher(int keylen,byte* key,byte data[16], byte out[16]){
	
	//declarations
	void keyexp(int Nb,int Nr, int Nk, byte key[4*Nk],byte expkey[4][Nb*(Nr+1)]);
	void addroundkey(int Nb, int Nr, byte state[4][Nb], byte expkey[4][Nb*(Nr+1)],int rnd);
	byte bytemult(byte a,byte b);
	void invsubbytes(int Nb, byte state[][Nb]);
	void invshiftrows(int Nb, byte state[4][Nb]);
	void invmixcolumns(int Nb, byte state[4][Nb]);
	byte bits2char(int bits[]);
	int* char2bits(byte c,int *bits);
	int Nr;
	int Nk;
	if(keylen==128){Nr=10; Nk=4;}
	else if(keylen==192){Nr=12; Nk=6;}
	else if(keylen==256){Nr=14; Nk=8;}
	else{printf("wrong key size"); exit(1);}
	int Nb = 4; /*idk why*/
	
	//initialization of the state as a 2d array of bytes
	byte expandedkey[4][Nb*(Nr+1)]; 
	keyexp(Nb,Nr,Nk,key,expandedkey);
	byte state[4][Nb];
	for(int i=0; i<4;i++){
		for(int j=0;j<Nb;j++){
			state[i][j]=data[4*j+i];
			}
		}
		


	//cipher
	addroundkey(Nb,Nr,state,expandedkey,Nr);

	for(int i=Nr-1;i>0;i--){
		invshiftrows(Nb,state);
		invsubbytes(Nb,state);
		addroundkey(Nb,Nr,state,expandedkey,i);
		invmixcolumns(Nb,state);
		}

	invshiftrows(Nb,state);	
	invsubbytes(Nb,state);

	addroundkey(Nb,Nr,state,expandedkey,0);	
	//outputing the state in the output
	for(int i=0; i<4;i++){
		for(int j=0;j<Nb;j++){
			out[4*j+i] = state[i][j];
			}
		}
}



//*---------------Fonctions utilisées dans le decipher aes---------------*//


/*-----invSbox-----*/ //marche
//input: a byte 'a'
//output: a byte 'res' = invSbox(a)
//purpose: used in decipheraes

byte invsbox(byte a){
	byte bits2char(int bits[]);
	int* char2bits(byte c,int *bits);
	byte bytemult(byte a, byte b);
	int bitsc[8];
	char2bits(5,bitsc);			//99 corresponds to the c of the nist specification

	int bitsa[8];
	char2bits(a,bitsa);			//accesses the bits of the inverse
	int bitsatransf[8];	    
	for(int i=0; i<8;i++){			//applying the needed XORs to the bits
		bitsatransf[i]= bitsa[(i+2)%8] ^ bitsa[(i+5)%8] ^ bitsa[(i+7)%8] ^ bitsc[i];	
		}
	byte atransf = bits2char(bitsatransf);
	if(a==99){return 0;}
	else{
		byte res = 0;
		while(bytemult(atransf,res)!=1){			//calculate the inverse of a thanks to bytemult through an exhaustive research
			res+=1;
			if(res==256){printf("inverse non trouvé pour la Sbox!");return 0;}
			}
		return res;
    	}
    }

/*-----invsubbytes-----*/ //OK MARCHE
//input: an int 'Nb' and a 2d array 'state
//output: none, in-place change of the array 'state'
//purpose: used in aes

void invsubbytes(int Nb, byte state[][Nb]){
	byte invsbox(byte a);
	for(int i=0; i<4;i++){
		for(int j=0; j<Nb;j++){			//straightforward, applies the Sbox to each byte of the state
			state[i][j]=invsbox(state[i][j]);
			}
		}
	}


/*-----invmixcolumns-----*/ //OK?
//input: an int Nb and a 2d array 'state'
//output: none, in-place change of the array 'expkey'
//purpose: used in aes

void invmixcolumns(int Nb, byte state[4][Nb]){
	byte bytemult(byte a, byte b);
	byte buffer[4];
	for(int j=0;j<Nb;j++){
		for(int i=0;i<4;i++){buffer[i]= state[i][j];}			//straightforward, applies the XORs specified in the nist specification paper
		state[0][j] = bytemult(buffer[0],14) ^ bytemult(buffer[1],11) ^ bytemult(buffer[2],13) ^ bytemult(buffer[3],9);
		state[1][j] = bytemult(buffer[0],9)  ^ bytemult(buffer[1],14) ^ bytemult(buffer[2],11) ^ bytemult(buffer[3],13);
		state[2][j] = bytemult(buffer[0],13) ^ bytemult(buffer[1],9)  ^ bytemult(buffer[2],14) ^ bytemult(buffer[3],11);
		state[3][j] = bytemult(buffer[0],11) ^ bytemult(buffer[1],13) ^ bytemult(buffer[2],9)  ^ bytemult(buffer[3],14);
			}
	}


/*-----invshiftrows-----*/ //OK MARCHE
//input: an int 'Nb' and a byte 2d array 'state'
//output: none, in-place change of the array 'state'
//purpose: used in aes

void invshiftrows(int Nb, byte state[4][Nb]){
	byte buffer[3];			//the buffers are here to preserve the first bytes that'll be overwritten
	buffer[0]=state[1][3];
	state[1][3]=state[1][2];
	state[1][2]=state[1][1];
	state[1][1]=state[1][0];
	state[1][0]=buffer[0];
	
	buffer[0]=state[2][2];
	buffer[1]=state[2][3];
	state[2][3]=state[2][1];
	state[2][2]=state[2][0];
	state[2][1]=buffer[1];
	state[2][0]=buffer[0];

	buffer[0]=state[3][1];
	buffer[1]=state[3][2];
	buffer[2]=state[3][3];
	state[3][3]=state[3][0];
	state[3][2]=buffer[2];
	state[3][1]=buffer[1];
	state[3][0]=buffer[0];
	}








