#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
typedef unsigned char byte;
int A=486662;
int B=1;
typedef struct {mpz_t x; mpz_t y; mpz_t z;} apoint; 
typedef struct {mpz_t x; mpz_t z;} axpoint;			
typedef apoint point[1]; //we need to define the points, and not only the xpoints for those functions
typedef axpoint xpoint[1];


void point_norm(point p){
	void point_mod(point p);
	mpz_t order;mpz_init(order);
	mpz_ui_pow_ui(order,2, 255);
	mpz_sub_ui(order,order,19);
	mpz_t quotient;
	mpz_init(quotient);
	int res = mpz_invert(quotient, p->z,order);
	if(res=0){printf("inverse of z not found!");exit(1);}
	mpz_mul(p->x,p->x,quotient);
	mpz_mul(p->y,p->y,quotient);
	mpz_mul(p->z,p->z,quotient);
	point_mod(p);
	mpz_clear(order);
	mpz_clear(quotient);
	}


void point_mod(point p){ //in place change of p, put its coordinate to mod 'order' 
	mpz_t order;mpz_init(order);
	mpz_ui_pow_ui(order,2, 255);
	mpz_sub_ui(order,order,19);
	mpz_mod(p->x,p->x,order);
	mpz_mod(p->y,p->y,order);
	mpz_mod(p->z,p->z,order);
	mpz_clear(order);
	}
	
void Xproj(xpoint p, const  point q){
	mpz_set(p->x,q->x);
	mpz_set(p->z,q->z);
	}

void point_init(point p){
	mpz_init(p->x);
	mpz_init(p->y);
	mpz_init(p->z);
	}

void point_free(point p){
	mpz_clear(p->x);
	mpz_clear(p->y);
	mpz_clear(p->z);
	}

void point_copy(point p, const point q){
	mpz_set(p->x,q->x);
	mpz_set(p->y,q->y);
	mpz_set(p->z,q->z);
	}

	
//used to recover the y coordinate of (Xq,Zq)	
void recover(point result, const point p, const xpoint q, const xpoint pplusq){
		mpz_t v1,v2,v3,v4;
		mpz_init(v1);mpz_init(v2);mpz_init(v3);mpz_init(v4);		
		mpz_mul(v1,p->x,q->z);
		mpz_add(v2,q->x,v1);
		mpz_sub(v3,q->x,v1);
		mpz_mul(v3,v3,v3);
		mpz_mul(v3,v3,pplusq->x);
		mpz_set_ui(v1, A);
		mpz_mul_ui(v1,v1,2);
		mpz_mul(v1,v1,q->z); 
		mpz_add(v2,v2,v1);		
		
		mpz_mul(v4,p->x,q->x);
		mpz_add(v4,v4,q->z);		
		mpz_mul(v2,v2,v4);
		mpz_mul(v1,v1,q->z);
		mpz_sub(v2,v2,v1);
		mpz_mul(v2,v2,pplusq->z);
		mpz_sub(result->y,v2,v3);
		
		mpz_set_ui(v1, B);
		mpz_mul_ui(v1,v1,2);
		mpz_mul(v1,v1,p->y); 
		mpz_mul(v1,v1,q->z);		
		mpz_mul(v1,v1,pplusq->z);
		mpz_mul(result->x,v1,q->x);
		mpz_mul(result->z,v1,q->z);
		point_mod(result);
		mpz_clear(v1);mpz_clear(v2);
		mpz_clear(v3);mpz_clear(v4);
	}



//this function takes a point having 3 coordinates, and computes [k]P

void scalarmult(point result,const mpz_t k, const point p){
	void ladder(xpoint x0,xpoint x1, const mpz_t k, const xpoint p);
	void recover(point result, const point p, const xpoint q, const xpoint pplusq);
	xpoint x0; xpoint x1;
	xpoint_init(x0);xpoint_init(x1);
	xpoint pproj; xpoint_init(pproj);
	Xproj(pproj,p); //pproj = (Xp,Zp)
	ladder(x0,x1,k,pproj);
	recover(result,p,x0,x1);
	xpoint_free(x0);xpoint_free(x1);
	xpoint_free(pproj);
	}


