/**
 \file 		djn.cpp
 \author 	Daniel Demmler
 \copyright Copyright (C) 2015 EC SPRIDE - daniel.demmler@ec-spride.de

 \brief		A library implementing the Damgaard Jurik Nielsen cryptosystem with s=1 (Same properties as Paillier, but more efficient).
 based on:<br>
 libdjn - A library implementing the Paillier cryptosystem.
 (http://hms.isi.jhu.edu/acsc/libdjn/)
 */

/*
 libdjn - v0.9
 A library implementing the Damgaard Jurik Nielsen cryptosystem with s=1 (~Paillier).
 based on:
 libpaillier - A library implementing the Paillier cryptosystem.
 (http://hms.isi.jhu.edu/acsc/libpaillier/)

 2015 EC SPRIDE
 daniel.demmler@ec-spride.de

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 General Public License for more details.
 */

#include "djn.h"

#define DEBUG 0
#define CHECKSIZE 0

void djn_complete_pubkey(unsigned int modulusbits, djn_pubkey_t** pub, mpz_t n, mpz_t h) {
	*pub = (djn_pubkey_t*) malloc(sizeof(djn_pubkey_t));

	/* initialize our integers */
	mpz_init((*pub)->n);
	mpz_init((*pub)->n_squared);
	mpz_init((*pub)->h);
	mpz_init((*pub)->h_s);

	mpz_set((*pub)->n, n);
	mpz_set((*pub)->h, h);
	mpz_mul((*pub)->n_squared, n, n);
	mpz_powm((*pub)->h_s, h, n, (*pub)->n_squared);
	(*pub)->bits = modulusbits;
	(*pub)->rbits = modulusbits % 2 ? modulusbits / 2 + 1 : modulusbits / 2; // rbits = ceil(bits/2)

}

void djn_keygen(unsigned int modulusbits, djn_pubkey_t** pub, djn_prvkey_t** prv) {
	mpz_t test, x;
	gmp_randstate_t rnd;

	/* allocate the new key structures */
	*pub = (djn_pubkey_t*) malloc(sizeof(djn_pubkey_t));
	*prv = (djn_prvkey_t*) malloc(sizeof(djn_prvkey_t));

	/* initialize our integers */
	mpz_init((*pub)->n);
	mpz_init((*pub)->n_squared);
	mpz_init((*pub)->h);
	mpz_init((*pub)->h_s);

	mpz_init((*prv)->lambda);
	mpz_init((*prv)->lambda_inverse);
	mpz_init((*prv)->p);
	mpz_init((*prv)->q);
	mpz_init((*prv)->p_squared);
	mpz_init((*prv)->q_squared);
	mpz_init((*prv)->q_inverse);
	mpz_init((*prv)->q_squared_inverse);
	mpz_init((*prv)->p_minusone);
	mpz_init((*prv)->q_minusone);
	mpz_init((*prv)->ordpsq);
	mpz_init((*prv)->ordqsq);
	mpz_init(test);
	mpz_init(x);

	gmp_randinit_default(rnd);
	gmp_randseed_ui(rnd, rand());

	do {
		// choose bits of p and q randomly
		mpz_urandomb((*prv)->p, rnd, modulusbits / 2);
		mpz_urandomb((*prv)->q, rnd, modulusbits / 2);

		// set highest bit to 1 to ensure high length
		mpz_setbit((*prv)->p, modulusbits / 2);
		mpz_setbit((*prv)->q, modulusbits / 2);

		//find next primes
		do {
			mpz_nextprime((*prv)->p, (*prv)->p);
		} while (!mpz_tstbit((*prv)->p, 1)); //make sure p mod 4 = 3

		do {
			mpz_nextprime((*prv)->q, (*prv)->q);
		} while (!mpz_cmp((*prv)->p, (*prv)->q) || !mpz_tstbit((*prv)->q, 1)); //make sure p!=q and q mod 4 = 3

		/* p-1 and q-1 */
		mpz_sub_ui((*prv)->p_minusone, (*prv)->p, 1);
		mpz_sub_ui((*prv)->q_minusone, (*prv)->q, 1);

		mpz_gcd(test, (*prv)->p_minusone, (*prv)->q_minusone);

	} while (mpz_cmp_ui(test, 2)); // make sure gcd(p-1,q-1)=2

	//} while((mpz_cmp_ui(test,2) || !mpz_tstbit((*pub)->n, modulusbits - 1) ); // make sure gcd(p-1,q-1)=2 and first bit of n is set

	//complete_pubkey(*pub);

	/* compute the public modulus n = p q */
	mpz_mul((*pub)->n, (*prv)->p, (*prv)->q);
	mpz_mul((*pub)->n_squared, (*pub)->n, (*pub)->n);

#if DEBUG
	if (!mpz_tstbit((*pub)->n, modulusbits - 1)) {
		printf("n too small!?\n");
	}
#endif

	/* p^2 and q^2 */
	mpz_mul((*prv)->p_squared, (*prv)->p, (*prv)->p);
	mpz_mul((*prv)->q_squared, (*prv)->q, (*prv)->q);
	mpz_sub((*prv)->ordpsq, (*prv)->p_squared, (*prv)->p);
	mpz_sub((*prv)->ordqsq, (*prv)->q_squared, (*prv)->q);

	/* computer multiplicative inverse of q mod p and q^2 mod p^2 for CRT*/
	mpz_invert((*prv)->q_inverse, (*prv)->q, (*prv)->p);
	mpz_invert((*prv)->q_squared_inverse, (*prv)->q_squared, (*prv)->p_squared);

	/* save one multiplication for CRT */
	mpz_mul((*prv)->q_squared_inverse, (*prv)->q_squared_inverse, (*prv)->q_squared);
	mpz_mul((*prv)->q_inverse, (*prv)->q_inverse, (*prv)->q);

#if DEBUG
	gmp_printf("p = %Zd\nq = %Zd\nn = %Zd\nn^2 = %Zd\n", (*prv)->p, (*prv)->q, (*pub)->n, (*pub)->n_squared);
#endif

	/* pick random x in Z_n^* */
	do {
		mpz_urandomm(x, rnd, (*pub)->n);
		mpz_gcd(test, x, (*pub)->n);
	} while (mpz_cmp_ui(test, 1));

//	gmp_printf("x = %Zd\n", x);

	mpz_mul(x, x, x);
//	gmp_printf("x^2 = %Zd\n", x);
	mpz_neg(x, x);
//	gmp_printf("-x^2 = %Zd\n", x);
	mpz_mod((*pub)->h, x, (*pub)->n);
//	mpz_powm((*pub)->h_s, (*pub)->h, (*pub)->n, (*pub)->n_squared);
	djn_pow_mod_n_squared_crt((*pub)->h_s, (*pub)->h, (*pub)->n, *pub, *prv);

	(*pub)->bits = modulusbits;
	(*pub)->rbits = modulusbits % 2 ? modulusbits / 2 + 1 : modulusbits / 2; // rbits = ceil(bits/2)

	/* compute the private key lambda = lcm(p-1,q-1) = (p-1)(q-1)/2 */
	//mpz_lcm((*prv)->lambda, (*prv)->p_minusone, (*prv)->q_minusone);
	mpz_mul((*prv)->lambda, (*prv)->p_minusone, (*prv)->q_minusone);
	mpz_fdiv_q_2exp((*prv)->lambda, (*prv)->lambda, 1); // division by two

	/* compute multiplicative inverse of lambda */
	mpz_invert((*prv)->lambda_inverse, (*prv)->lambda, (*pub)->n);

#if DEBUG
	gmp_printf("h = %Zd\nh_s = %Zd\n", (*pub)->h, (*pub)->h_s);
	printf("rbits = %d, bits = %d\n", (*pub)->rbits, (*pub)->bits);
	gmp_printf("lambda = %Zd\nlambda_inverse = %Zd\n", (*prv)->lambda, (*prv)->lambda_inverse);
#endif

	/* clear temporary integers and randstate */
	mpz_clears(x, test, NULL);
	gmp_randclear(rnd);
}

/**
 * encrypt plaintext to res
 */
void djn_encrypt(mpz_t res, djn_pubkey_t* pub, mpz_t plaintext, gmp_randstate_t rnd) {
	mpz_t r;
	mpz_init(r);

#if CHECKSIZE
	if (mpz_cmp(plaintext, pub->n) >= 0) {
		printf("WARNING: m>=N!\n");
	}
#endif

	/* pick random blinding factor r */
	mpz_urandomb(r, rnd, pub->rbits);

#if DEBUG
	gmp_printf("r = %Zd\n", r);
#endif

	mpz_mul(res, plaintext, pub->n);
	mpz_add_ui(res, res, 1);
	mpz_mod(res, res, pub->n_squared);

	mpz_powm(r, pub->h_s, r, pub->n_squared);

	mpz_mul(res, res, r);
	mpz_mod(res, res, pub->n_squared);

	mpz_clear(r);
}

/**
 * encrypt plaintext using crt if private key is known
 */
void djn_encrypt_crt(mpz_t res, djn_pubkey_t* pub, djn_prvkey_t* prv, mpz_t plaintext, gmp_randstate_t rnd) {
	mpz_t r;
	mpz_init(r);

#if CHECKSIZE
	if (mpz_cmp(plaintext, pub->n) >= 0) {
		printf("WARNING: m>=N!\n");
	}
#endif

	/* pick random blinding factor r */
	mpz_urandomb(r, rnd, pub->rbits);

#if DEBUG
	gmp_printf("r = %Zd\n", r);
#endif

	mpz_mul(res, plaintext, pub->n);
	mpz_add_ui(res, res, 1);
	mpz_mod(res, res, pub->n_squared);

	djn_pow_mod_n_squared_crt(r, pub->h_s, r, pub, prv);

	mpz_mul(res, res, r);
	mpz_mod(res, res, pub->n_squared);

	mpz_clear(r);
}

/**
 * mpz_t version of encrypt_crt
 */
void djn_encrypt_fb(mpz_t res, djn_pubkey_t* pub, mpz_t plaintext, gmp_randstate_t rnd) {
	mpz_t r;
	mpz_init(r);

#if checksize
	if (mpz_cmp(plaintext, pub->n) >= 0) {
		printf("WARNING: m>=N!\n");
	}
#endif

	/* pick random blinding factor r */
	mpz_urandomb(r, rnd, pub->rbits);

#if DEBUG
	gmp_printf("r = %Zd\n", r);
#endif

	mpz_mul(res, plaintext, pub->n);
	mpz_add_ui(res, res, 1);
	mpz_mod(res, res, pub->n_squared);

	// r = h_s ^ r
	fbpowmod_g(r, r);

	mpz_mul(res, res, r);
	mpz_mod(res, res, pub->n_squared);

	mpz_clear(r);
}

/**
 * decrypt, using CRT, assumes res to be initialized
 */
void djn_decrypt(mpz_t res, djn_pubkey_t* pub, djn_prvkey_t* prv, mpz_t ciphertext) {
	/* powmod using CRT */
	djn_pow_mod_n_squared_crt(res, ciphertext, prv->lambda, pub, prv);

	mpz_sub_ui(res, res, 1);
	mpz_divexact(res, res, pub->n);
	mpz_mul(res, res, prv->lambda_inverse);
	mpz_mod(res, res, pub->n);
}

/**
 * plain decrypt version without crt (= much slower), assumes res to be initialized
 */
void djn_decrypt_plain(mpz_t res, djn_pubkey_t* pub, djn_prvkey_t* prv, mpz_t ciphertext) {
	mpz_powm(res, ciphertext, prv->lambda, pub->n_squared);

	mpz_sub_ui(res, res, 1);
	mpz_divexact(res, res, pub->n);
	mpz_mul(res, res, prv->lambda_inverse);
	mpz_mod(res, res, pub->n);
}

void djn_freepubkey(djn_pubkey_t* pub) {
	mpz_clear(pub->n);
	mpz_clear(pub->h);
	mpz_clear(pub->n_squared);
	mpz_clear(pub->h_s);
	free(pub);
}

void djn_freeprvkey(djn_prvkey_t* prv) {
	mpz_clears(prv->lambda, prv->lambda_inverse, prv->ordpsq, prv->ordqsq, prv->p, prv->p_minusone, prv->p_squared, prv->q, prv->q_minusone, prv->q_squared, prv->q_inverse,
			prv->q_squared_inverse,
			NULL);

	free(prv);
}

/* calculate base^exp mod n using fermats little theorem and CRT */
void djn_pow_mod_n_crt(mpz_t res, const mpz_t base, const mpz_t exp, const djn_pubkey_t* pub, const djn_prvkey_t* prv) {
	mpz_t temp, cp, cq;
	mpz_inits(cp, cq, temp, NULL);

	/* smaller exponents due to fermat: e mod (p-1), e mod (q-1) */
	mpz_mod(cp, exp, prv->p_minusone);
	mpz_mod(cq, exp, prv->q_minusone);

	/* smaller exponentiations of base mod p, q */
	mpz_mod(temp, base, prv->p);
	mpz_powm(cp, temp, cp, prv->p);

	mpz_mod(temp, base, prv->q);
	mpz_powm(cq, temp, cq, prv->q);

	/* CRT to calculate base^exp mod (pq) */
	mpz_sub(cp, cp, cq);
	mpz_addmul(cq, cp, prv->q_inverse);
	mpz_mod(res, cq, pub->n);

	mpz_clears(cp, cq, temp, NULL);
}

/* calculate base^exp mod n^2 using fermats little theorem and CRT */
void djn_pow_mod_n_squared_crt(mpz_t res, const mpz_t base, const mpz_t exp, const djn_pubkey_t* pub, const djn_prvkey_t* prv) {
	mpz_t temp, cp, cq;
	mpz_inits(cp, cq, temp, NULL);

	/* smaller exponents due to fermat: e mod (p-1), e mod (q-1) */
	mpz_mod(cp, exp, prv->ordpsq);
	mpz_mod(cq, exp, prv->ordqsq);

	/* smaller exponentiations of base mod p^2, q^2 */
	mpz_mod(temp, base, prv->p_squared);
	mpz_powm(cp, temp, cp, prv->p_squared);

	mpz_mod(temp, base, prv->q_squared);
	mpz_powm(cq, temp, cq, prv->q_squared);

	/* CRT to calculate base^exp mod n^2 */
	mpz_sub(cp, cp, cq);
	mpz_addmul(cq, cp, prv->q_squared_inverse);
	mpz_mod(res, cq, pub->n_squared);

	mpz_clears(cp, cq, temp, NULL);
}
