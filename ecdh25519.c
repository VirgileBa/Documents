#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

//SOME UNUSED BUT IMPLEMENTED FUNCTIONS CAN BE FOUND IN ecdhrest.c

/*
 * exemples of vectors: https://tools.ietf.org/html/rfc7748#section-6.1 
 * */


//All programs using GMP must link against
//thelibgmp library. On a typical Unix-like system this
//can be done with ‘-lgmp’, for example
//gcc myprogram.c -lgmp
//https://gmplib.org/manual

typedef unsigned char byte;
int A=486662;
int B=1;
typedef struct {mpz_t x; mpz_t z;} axpoint;	//X(point)
typedef axpoint xpoint[1];	//enables the points to be passed as argument of functions



int main(){
	void X25519(byte output[32],const byte scal[32],const byte ucoord[32], char* choice);
	                  
	printf("\n\n\n------------------------------------------------------------------------------");
	printf("\n------------------------------------------------------------------------------");
	printf("\nles exemples sont ceux de cet url. ces urls sont au debut de ce .c prets a etre copies:\n");      
	printf("\nhttps://tools.ietf.org/html/rfc7748#section-6.1");
	printf("\n\n------------------------------------------------------------------------------");
	

	//scalar inputs of the exemples 
	byte ascal[32] = {'\x77', '\x07', '\x6d', '\x0a', '\x73', '\x18', '\xa5',
	'\x7d', '\x3c', '\x16', '\xc1', '\x72', '\x51', '\xb2', '\x66', '\x45',
	'\xdf', '\x4c', '\x2f', '\x87', '\xeb', '\xc0', '\x99', '\x2a', '\xb1',
	'\x77', '\xfb', '\xa5', '\x1d', '\xb9', '\x2c', '\x2a'};
	
	printf("\nscalar a:\n");
	for(int i=0; i<32;i++){
		if(i%4==0){printf(" ");}
		printf("%02X",ascal[i]);
		}

	byte bscal[32] = {'\x5d', '\xab', '\x08', '\x7e', '\x62', '\x4a', '\x8a',
	'\x4b', '\x79', '\xe1', '\x7f', '\x8b', '\x83', '\x80', '\x0e', '\xe6',
	'\x6f', '\x3b', '\xb1', '\x29', '\x26', '\x18', '\xb6', '\xfd', '\x1c',
	'\x2f', '\x8b', '\x27', '\xff', '\x88', '\xe0', '\xeb'};

	printf("\n\nscalar b:\n");
	for(int i=0; i<32;i++){
		if(i%4==0){printf(" ");}
		printf("%02X",bscal[i]);
		}
	printf("\n\n------------------------------------------------------------------------------");

	//encoded coordinates of the base point P
	byte Pcoord[32];
	Pcoord[0]=9;
	for(int i=1; i<32;i++){Pcoord[i]=0;}

	byte output[32]; //will contain ALice's public key
	byte output2[32]; //will contain the shared secret
	
	//choose uniform to use the uniform ladder, anything else is the normal one
	char * choice ="uniform";
	
	X25519(output,ascal,Pcoord,choice);
	X25519(output2,bscal,output,choice);

	//output display
	printf("\nAlice's public key([a]P):\n");
	for(int i=0; i<32;i++){
		if(i%4==0){printf(" ");}
		printf("%02X",output[i]);
		}
	
	printf("\n\nShared secret([ba]P):\n");
	for(int i=0; i<32;i++){
		if(i%4==0){printf(" ");}
		printf("%02X",output2[i]);
		}	
	
	printf("\n\n------------------------------------------------------------------------------");
	printf("\n------------------------------------------------------------------------------\n\n\n");
}

//the fonction computes the X coordinate of [scal]P and encode it in output
void X25519(byte output[32],const byte scal[32],const byte ucoord[32], char* choice){
	//declarations
	void uniformladder(xpoint x0,xpoint x1, const mpz_t k, const xpoint p);
	void ladder(xpoint x0,xpoint x1, const mpz_t k, const xpoint p);
	void xpoint_free(xpoint p);
	void xpoint_init(xpoint p);
	void encodeucoord(byte result[32], const mpz_t input);
	void decodescalar(mpz_t result, const byte input[32]);
	void decodeucoord(mpz_t result, const byte input[32]);
	void xpoint_norm(xpoint p);
	
	//decodes the scalar input
	mpz_t scalar;
	mpz_init(scalar);
	decodescalar(scalar,scal);
	
	//decodes the x coordinate of the input point
	xpoint P;
	xpoint_init(P);
	decodeucoord(P->x,ucoord);
	mpz_set_ui(P->z,1);
	
	//calculate the x coordinate of [sclar]P
	xpoint result;
	xpoint_init(result);
	xpoint x1;
	xpoint_init(x1);
	if(choice="uniform"){uniformladder(result,x1,scalar,P);}
	else{ladder(result,x1,scalar,P);}
	xpoint_free(x1);
	xpoint_norm(result); //normalise ( (Xp,Zp) -> (Xp/Zp,1) )
	
	//encodes the x coordinate of the result in the output
	encodeucoord(output, result->x);
	//free the memory
	xpoint_free(P);
	xpoint_free(result);
	mpz_clear(scalar);
	}

void decode_little_endian(mpz_t result, const byte input[32]){
	mpz_t power, a;
	mpz_init(power);mpz_init(a);
	mpz_set_ui(power, 1);
	for(int i =0;i<32;i++){ //result = input[0] + 256*input[1] + 256^2 * input[2]+....
		mpz_set_ui(a, input[i]);
		mpz_mul(a,a,power);
		mpz_add(result, result, a);
		mpz_mul_ui(power, power,256);
		}
	mpz_clear(power);mpz_clear(a); //frees the memory
	}

void decodeucoord(mpz_t result, const byte input[32]){
	// the decoded x coordinate is the input read as little endian where
	// the most significant bit of the last byte is put to 0
	void decode_little_endian(mpz_t result, const byte input[32]);
	byte prepared_input[32];
	prepared_input[31]= input[31] & 0b01111111;
	for(int i=0;i<31;i++){prepared_input[i]=input[i];}	
	decode_little_endian(result, prepared_input);
	}

void encodeucoord(byte result[32], const mpz_t input){
	//it is just the decomposition in base 256
	mpz_t mask,transf;
	mpz_init(mask);mpz_init(transf);
	mpz_set_str(mask,"11111111",2);
	unsigned long int a;	
	for(int i=0;i<32;i++){
		mpz_fdiv_q_2exp(transf, input, 8*i); //right shift of i*8 bits
		mpz_and(transf,transf, mask); //recuperate the last 8 bits
		a=mpz_get_ui(transf); // the result of mpz_get_ui can't be a char, it has to be a long int,
		result[i]=a;		  // thus a is used as output and then copied in the result
		}
	mpz_clear(mask);
	}

void decodescalar(mpz_t result, const byte input[32]){
	//4 bits are set to 0, one to 1, the rest is just copied, then we decode as little endian
	void decode_little_endian(mpz_t result, const byte input[32]);
	byte prepared_input[32];
	prepared_input[0]= input[0] & 0b11111000;
	for(int i=1;i<31;i++){prepared_input[i]=input[i];}
	prepared_input[31]= (input[31] & 0b01111111)|0b01000000;
	decode_little_endian(result, prepared_input);
	}

void xpoint_norm(xpoint p){
	//declarations
	void xpoint_mod(xpoint p);
	mpz_t order;mpz_init(order);
	mpz_ui_pow_ui(order,2, 255);
	mpz_sub_ui(order,order,19);
	mpz_t quotient;
	mpz_init(quotient);
	
	//computations
	int res = mpz_invert(quotient, p->z,order); // puts the inverse of Zp [order] in quotient
	if(res=0){printf("inverse of z not found!");exit(1);}
	mpz_mul(p->x,p->x,quotient);	//dividing the coordinates by Zp
	mpz_mul(p->z,p->z,quotient);
	
	//finally, modulo and then freeing the memory
	xpoint_mod(p);
	mpz_clear(order);
	mpz_clear(quotient);
	}

//puts the coordinates of a point to their value mod order = 2^255-19
void xpoint_mod(xpoint p){
	mpz_t order;mpz_init(order);
	mpz_ui_pow_ui(order,2, 255);
	mpz_sub_ui(order,order,19);
	mpz_mod(p->x,p->x,order);
	mpz_mod(p->z,p->z,order);
	mpz_clear(order);
	}

//initiates a xpoint
void xpoint_init(xpoint p){
	mpz_init(p->x);
	mpz_init(p->z);
	}

//frees the memory of a xpoint
void xpoint_free(xpoint p){
	mpz_clear(p->x);
	mpz_clear(p->z);
	}
	
//copies the xpoint p into the xpoint q	
void xpoint_copy(xpoint p, const xpoint q){ //copy q into p
	mpz_set(p->x,q->x);
	mpz_set(p->z,q->z);
	}

//the xadd function, is forward, as in the pseudo algorithm 
void xadd(xpoint result, const xpoint p, const xpoint q, const xpoint pminusq){
	if(mpz_sgn(pminusq->z)==0){
		mpz_set_ui(result->x,0);
		mpz_set_ui(result->z,0);
		}
	else{
		mpz_t v0,v1,v2,v3,v4;
		mpz_init(v0);mpz_init(v1);mpz_init(v2);mpz_init(v3);mpz_init(v4);
		mpz_add(v0,p->x,p->z);
		mpz_sub(v1,q->x,q->z);
		mpz_mul(v1,v1,v0);
		mpz_sub(v0,p->x,p->z);
		mpz_add(v2,q->x,q->z);
		
		mpz_mul(v2,v2,v0);
		mpz_add(v3,v1,v2);
		mpz_mul(v3,v3,v3);
		mpz_sub(v4,v1,v2);
		mpz_mul(v4,v4,v4);
		
		mpz_mul(result->x,v3,pminusq->z);
		mpz_mul(result->z,v4,pminusq->x);
		xpoint_mod(result);
		mpz_clear(v0);mpz_clear(v1);mpz_clear(v2);mpz_clear(v3);mpz_clear(v4);
		}
	}

//the xdbl function, is forward, as in the pseudo algorithm
void xdbl(xpoint result, const xpoint p){	
	if(mpz_sgn(p->z)==0){
		mpz_set_ui(result->x,0);
		mpz_set_ui(result->z,0);
		}
	else{
		mpz_t v1, v2,v3;
		mpz_init(v1);mpz_init(v2);mpz_init(v3);
		mpz_add(v1,p->x,p->z);
		mpz_mul(v1,v1,v1);
		mpz_sub(v2,p->x,p->z);
		mpz_mul(v2,v2,v2);
		
		mpz_mul(result->x,v2,v1);
		mpz_sub(v1,v1,v2);
		mpz_set_ui(v3, A);
		mpz_add_ui(v3,v3,2);
		mpz_cdiv_q_ui(v3, v3,4);
		mpz_mul(v3,v3,v1);
		mpz_add(v3,v3,v2);
		mpz_mul(result->z,v3,v1);
		xpoint_mod(result);
		mpz_clear(v1);mpz_clear(v2);mpz_clear(v3);
		}
	}
	
//the ladder algorithm, computes and puts ([k]P, [k+1]P) in (x0,x1)
void ladder(xpoint x0,xpoint x1, const mpz_t k, const xpoint p){
	size_t n= mpz_sizeinbase(k,2);//size of k in base 2; aka the number of bits
	xpoint_copy(x0,p);
	xdbl(x1,p);
	for(int i =n-2;i>=0;i--){ //-2 because it has one less power of 2 than it has bits
		if(mpz_tstbit(k, i)==0){ //if ki=0:....
			xadd(x1,x0,x1,p);
			xdbl(x0,x0);
			}
		else{
			xadd(x0,x0,x1,p); //if ki=1:....
			xdbl(x1,x1);
			}
		}
	}


void swap(xpoint res0,xpoint res1, const int k,const xpoint x0, const xpoint x1){
		mpz_t mask;mpz_t v;
		mpz_init(mask);mpz_init(v);
	if(k==0){mpz_set_ui(mask,0);}
	if(k==1){
		mpz_ui_pow_ui(mask,2, 255); // this mask is long enough because x0,x1 <255
		mpz_sub_ui(mask, mask,1);
		}
	mpz_xor(v, x0->x, x1->x);
	mpz_and(v, mask, v);
	mpz_xor(res0->x, x0->x, v);
	mpz_xor(res1->x, x1->x, v);
	
	mpz_xor(v, x0->z, x1->z);
	mpz_and(v, mask, v);
	mpz_xor(res0->z, x0->z, v);
	mpz_xor(res1->z, x1->z, v);
	}


void uniformladder(xpoint x0,xpoint x1, const mpz_t k, const xpoint p){
	size_t n= mpz_sizeinbase(k,2);//size of k in base 2; aka the number of bits
	xdbl(x0,p);
	xpoint_copy(x1,p);
	int a;
	for(int i =n-2;i>=0;i--){ //-2 because it has one less power of 2 than it has bits
		a = mpz_tstbit(k, i) ^ mpz_tstbit(k, (i+1));
		swap(x0,x1,a,x0,x1);
		xadd(x1,x0,x1,p);
		xdbl(x0,x0);
		}
	swap(x0,x1,mpz_tstbit(k, 0),x0,x1);
	}



