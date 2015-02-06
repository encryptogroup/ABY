/**
 \file 		dgk.h
 \author 	Daniel Demmler
 \copyright Copyright (C) 2015 EC SPRIDE - daniel.demmler@ec-spride.de

 \brief		 A library implementing the DGK crypto system with full decryption
 Thanks to Marina Blanton for sharing her Miracl DGK implementation from
 M. Blanton and P. Gasti, "Secure and efficient protocols for iris and fingerprint identification" (ESORICS’11)
 with us. We used it as a template for this GMP version.

 The implementation structure was inspired by
 libpailler - A library implementing the Paillier crypto system. (http://hms.isi.jhu.edu/acsc/libpaillier/)

 */

/*
 libdgk - v0.9
 A library implementing the DGK crypto system with full decryption

 Thanks to Marina Blanton for sharing her Miracl DGK implementation from
 M. Blanton and P. Gasti, "Secure and efficient protocols for iris and fingerprint identification" (ESORICS’11)
 with us. We used it as a template for this GMP version.

 The implementation structure was inspired by
 libpailler - A library implementing the Paillier crypto system. (http://hms.isi.jhu.edu/acsc/libpaillier/)

 Copyright (C) 2015 EC SPRIDE
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

#include "dgk.h"

#define DGK_CHECKSIZE 0

// number of test encryptions and decryptions that are performed to verify a generated key. This will take time, but more are better.
#define KEYTEST_ITERATIONS 1000

//array holding the powers of two
mpz_t* powtwo;

//array for holding temporary values
mpz_t* gvpvqp;

void dgk_complete_pubkey(unsigned int modulusbits, unsigned int lbits, dgk_pubkey_t** pub, mpz_t n, mpz_t g, mpz_t h) {
	*pub = (dgk_pubkey_t*) malloc(sizeof(dgk_pubkey_t));

	mpz_init((*pub)->n);
	mpz_init((*pub)->u);
	mpz_init((*pub)->h);
	mpz_init((*pub)->g);

	mpz_set((*pub)->n, n);
	mpz_setbit((*pub)->u, 2 * lbits + 2);
	mpz_set((*pub)->g, g);
	mpz_set((*pub)->h, h);

	(*pub)->bits = modulusbits;
	(*pub)->lbits = 2 * lbits + 2;
}

void dgk_keygen(unsigned int modulusbits, unsigned int lbits, dgk_pubkey_t** pub, dgk_prvkey_t** prv) {
	mpz_t tmp, tmp2, f1, f2, exp1, exp2, exp3, xp, xq;
	gmp_randstate_t rnd;

	unsigned int found = 0, i;

	//printf("Keygen %u %u\n", modulusbits, lbits);

	/* allocate the new key structures */
	*pub = (dgk_pubkey_t*) malloc(sizeof(dgk_pubkey_t));
	*prv = (dgk_prvkey_t*) malloc(sizeof(dgk_prvkey_t));

	/* initialize our integers */
	mpz_init((*pub)->n);
	mpz_init((*pub)->u);
	mpz_init((*pub)->h);
	mpz_init((*pub)->g);

	mpz_init((*prv)->vp);
	mpz_init((*prv)->vq);
	mpz_init((*prv)->p);
	mpz_init((*prv)->q);
	mpz_init((*prv)->p_minusone);
	mpz_init((*prv)->q_minusone);
	mpz_init((*prv)->pinv);
	mpz_init((*prv)->qinv);

	mpz_inits(tmp, tmp2, f1, f2, exp1, exp2, exp3, xp, xq, NULL);

	lbits = lbits * 2 + 2; // plaintext space needs to 2l+2 in our use case. probably not needed for general use, but four our MT generation.

	(*pub)->bits = modulusbits;
	(*pub)->lbits = lbits;

	gmp_randinit_default(rnd);
	gmp_randseed_ui(rnd, rand());

	// vp and vq are primes
	mpz_urandomb((*prv)->vp, rnd, 160);
	mpz_nextprime((*prv)->vp, (*prv)->vp);

	mpz_urandomb((*prv)->vq, rnd, 160);
	do {
		mpz_nextprime((*prv)->vq, (*prv)->vq);
	} while (mpz_cmp((*prv)->vp, (*prv)->vq) == 0);

	// u = 2^lbits. u is NOT a prime (different from original DGK to allow full and easy decryption. See Blanton/Gasti Paper for details).
	mpz_setbit((*pub)->u, lbits);

	// p
	while (!found) {
		mpz_urandomb(f1, rnd, modulusbits / 2 - 160 - lbits);
		mpz_nextprime(f1, f1);

		mpz_mul((*prv)->p, (*pub)->u, (*prv)->vp);
		mpz_mul((*prv)->p, f1, (*prv)->p);
		mpz_add_ui((*prv)->p, (*prv)->p, 1);
		found = mpz_probab_prime_p((*prv)->p, 50);
	}
	found = 0;

	// q
	while (!found) {
		mpz_urandomb(f2, rnd, modulusbits / 2 - 159 - lbits);
		mpz_nextprime(f2, f2);

		mpz_mul((*prv)->q, (*pub)->u, (*prv)->vq);
		mpz_mul((*prv)->q, f2, (*prv)->q);
		mpz_add_ui((*prv)->q, (*prv)->q, 1);
		found = mpz_probab_prime_p((*prv)->q, 50);
	}
	found = 0;

	// p-1, q-1 - this is currently not used
	mpz_sub_ui((*prv)->p_minusone, (*prv)->p, 1);
	mpz_sub_ui((*prv)->q_minusone, (*prv)->q, 1);

	// n = pq
	mpz_mul((*pub)->n, (*prv)->p, (*prv)->q);

	mpz_setbit(exp1, lbits - 1);

	mpz_mul(exp1, (*prv)->vp, exp1);
	mpz_mul(exp1, f1, exp1);
	mpz_mul(exp2, (*prv)->vp, (*pub)->u);
	mpz_mul(exp3, f1, (*pub)->u);

	// xp
	while (!found) {
		mpz_urandomm(xp, rnd, (*prv)->p);

		mpz_powm(tmp, xp, exp1, (*prv)->p);
		if (mpz_cmp_ui(tmp, 1) != 0) {
			mpz_powm(tmp, xp, exp2, (*prv)->p);
			if (mpz_cmp_ui(tmp, 1) != 0) {
				mpz_powm(tmp, xp, exp3, (*prv)->p);
				if (mpz_cmp_ui(tmp, 1) != 0) {
					found = 1;
				}
			}
		}
	}
	found = 0;

	mpz_setbit(exp1, lbits - 1);

	mpz_mul(exp1, (*prv)->vq, exp1);
	mpz_mul(exp1, f2, exp1);
	mpz_mul(exp2, (*prv)->vq, (*pub)->u);
	mpz_mul(exp3, f2, (*pub)->u);

	// xq
	while (!found) {
		mpz_urandomm(xq, rnd, (*prv)->q);

		mpz_powm(tmp, xq, exp1, (*prv)->q);
		if (mpz_cmp_ui(tmp, 1) != 0) {
			mpz_powm(tmp, xq, exp2, (*prv)->q);
			if (mpz_cmp_ui(tmp, 1) != 0) {
				mpz_powm(tmp, xq, exp3, (*prv)->q);
				if (mpz_cmp_ui(tmp, 1) != 0) {
					found = 1;
				}
			}
		}
	}

	// compute CRT: g = xp*q*(q^{-1} mod p) + xq*p*(p^{-1} mod q) mod n
	mpz_invert(tmp, (*prv)->q, (*prv)->p); // tmp = 1/q % p
	mpz_set((*prv)->qinv, tmp);
	mpz_mul(tmp, tmp, (*prv)->q); // tmp = tmp * q

	// tmp = xp*tmp % n
	mpz_mul(tmp, xp, tmp);
	mpz_mod(tmp, tmp, (*pub)->n);

	mpz_invert(tmp2, (*prv)->p, (*prv)->q); // tmp1 = 1/p % q
	mpz_set((*prv)->pinv, tmp2);
	mpz_mul(tmp2, tmp2, (*prv)->p); // tmp1 = tmp1*p

	// tmp1 = xq*tmp1 % n
	mpz_mul(tmp2, xq, tmp2);
	mpz_mod(tmp2, tmp2, (*pub)->n);

	// g = xp + xq % n
	mpz_add((*pub)->g, xq, xp);
	mpz_mod((*pub)->g, (*pub)->g, (*pub)->n);

	mpz_mul(tmp, f1, f2); // tmp = f1*f2
	mpz_powm((*pub)->g, (*pub)->g, tmp, (*pub)->n); // g = g^tmp % n

	mpz_urandomm((*pub)->h, rnd, (*pub)->n);

	mpz_mul(tmp, tmp, (*pub)->u);
	mpz_powm((*pub)->h, (*pub)->h, tmp, (*pub)->n); // h = h^tmp % n

	powtwo = (mpz_t*) malloc(sizeof(mpz_t) * lbits);
	gvpvqp = (mpz_t*) malloc(sizeof(mpz_t) * lbits);

	// array holding powers of two
	for (i = 0; i < lbits; i++) {
		mpz_init(powtwo[i]);
		mpz_setbit(powtwo[i], i);
	}

	mpz_powm(f1, (*pub)->g, (*prv)->vp, (*prv)->p); // gvpvq

	mpz_sub_ui(tmp2, (*pub)->u, 1); // tmp1 = u - 1

	for (i = 0; i < lbits; i++) {
		mpz_init(gvpvqp[i]);
		mpz_powm(gvpvqp[i], f1, powtwo[i], (*prv)->p);
		mpz_powm(gvpvqp[i], gvpvqp[i], tmp2, (*prv)->p);
	}

	/* clear temporary integers and randstate */
	mpz_clears(tmp, tmp2, f1, f2, exp1, exp2, exp3, xp, xq, NULL);
	gmp_randclear(rnd);

}

void dgk_encrypt_db(mpz_t res, dgk_pubkey_t* pub, mpz_t plaintext, gmp_randstate_t rnd) {
	mpz_t r;
	mpz_init(r);

#if DGK_CHECKSIZE
	mpz_setbit(r, (pub->lbits-2)/2);
	if (mpz_cmp(plaintext, r) >= 0) {
		gmp_printf("m: %Zd\nmax:%Zd\n", plaintext, r);
		printf("DGK WARNING: m too big!\n");
	}
#endif

	/* pick random blinding factor r */
	mpz_urandomb(r, rnd, 400); // 2.5 * 160 = 400 bit

	dbpowmod(res, pub->h, r, pub->g, plaintext, pub->n);

	mpz_clear(r);
}

void dgk_encrypt_fb(mpz_t res, dgk_pubkey_t* pub, mpz_t plaintext, gmp_randstate_t rnd) {
	mpz_t r;
	mpz_init(r);

#if DGK_CHECKSIZE
	mpz_setbit(r, (pub->lbits-2)/2);
	if (mpz_cmp(plaintext, r) >= 0) {
		gmp_printf("m: %Zd\nmax:%Zd\n", plaintext, r);
		printf("DGK WARNING: m too big!\n");
	}
#endif

	/* pick random blinding factor r */
	mpz_urandomb(r, rnd, 400); // 2.5 * 160 = 400 bit

	fbpowmod_h(r, r); //r = h^r
	fbpowmod_g(res, plaintext); //res = g^plaintext

	mpz_mul(res, res, r);
	mpz_mod(res, res, pub->n);

	mpz_clear(r);
}

void dgk_encrypt_plain(mpz_t res, dgk_pubkey_t* pub, mpz_t plaintext, gmp_randstate_t rnd) {
	mpz_t r;
	mpz_init(r);

#if DGK_CHECKSIZE
	mpz_setbit(r, (pub->lbits-2)/2);
	if (mpz_cmp(plaintext, r) >= 0) {
		gmp_printf("m: %Zd\nmax:%Zd\n", plaintext, r);
		printf("DGK WARNING: m too big!\n");
	}
#endif

	/* pick random blinding factor r */
	mpz_urandomb(r, rnd, 400); // 2.5 * 160 = 400 bit

	mpz_powm(r, pub->h, r, pub->n);
	mpz_powm(res, pub->g, plaintext, pub->n);

	mpz_mul(res, res, r);
	mpz_mod(res, res, pub->n);

	mpz_clear(r);
}

void dgk_encrypt_crt_db(mpz_t res, dgk_pubkey_t * pub, dgk_prvkey_t * prv, mpz_t plaintext, gmp_randstate_t rnd) {
	mpz_t r, ep;
	mpz_inits(r, ep, NULL);

#if DGK_CHECKSIZE
	mpz_setbit(r, (pub->lbits-2)/2);
	if (mpz_cmp(plaintext, r) >= 0) {
		gmp_printf("m: %Zd\nmax:%Zd\n", plaintext, r);
		printf("DGK WARNING: m too big!\n");
	}
#endif

	/* pick random blinding factor r */
	mpz_urandomb(r, rnd, 400); // 2.5 * 160 = 400 bit

	dbpowmod(ep, pub->h, r, pub->g, plaintext, prv->p);

	mpz_mul(res, ep, prv->q);
	mpz_mul(res, res, prv->qinv);
	mpz_mod(res, res, pub->n);

	dbpowmod(ep, pub->h, r, pub->g, plaintext, prv->q);

	mpz_mul(ep, ep, prv->p);
	mpz_mul(ep, ep, prv->pinv);
	mpz_mod(ep, ep, pub->n);

	mpz_add(res, res, ep);
	mpz_mod(res, res, pub->n);

	mpz_clears(r, ep, NULL);
}

void dgk_encrypt_crt(mpz_t res, dgk_pubkey_t * pub, dgk_prvkey_t * prv, mpz_t plaintext, gmp_randstate_t rnd) {
	mpz_t r, ep, eq;
	mpz_inits(r, ep, eq, NULL);

#if DGK_CHECKSIZE
	mpz_setbit(r, (pub->lbits-2)/2);
	if (mpz_cmp(plaintext, r) >= 0) {
		gmp_printf("m: %Zd\nmax:%Zd\n", plaintext, r);
		printf("DGK WARNING: m too big!\n");
	}
#endif

	/* pick random blinding factor r */
	mpz_urandomb(r, rnd, 400); // 2.5 * 160 = 400 bit

	// ep = h^r * g^plaintext % p
	mpz_powm(ep, pub->h, r, prv->p);
	mpz_powm(res, pub->g, plaintext, prv->p);
	mpz_mul(ep, ep, res);
	mpz_mod(ep, ep, prv->p);

	mpz_mul(res, ep, prv->q);
	mpz_mul(res, res, prv->qinv);
	mpz_mod(res, res, pub->n);

	// ep = h^r*g^plaintext % q
	mpz_powm(ep, pub->h, r, prv->q);
	mpz_powm(eq, pub->g, plaintext, prv->q);
	mpz_mul(ep, ep, eq);
	mpz_mod(ep, ep, prv->q);

	mpz_mul(ep, ep, prv->p);
	mpz_mul(ep, ep, prv->pinv);
	mpz_mod(ep, ep, pub->n);

	mpz_add(res, res, ep);
	mpz_mod(res, res, pub->n);

	mpz_clears(r, ep, eq, NULL);
}

void dgk_decrypt(mpz_t res, dgk_pubkey_t* pub, dgk_prvkey_t* prv, mpz_t ciphertext) {
	mpz_t y, yi;
	mpz_inits(y, yi, NULL);

	unsigned int i, xi[pub->lbits];

	mpz_powm(y, ciphertext, prv->vp, prv->p);

	mpz_set_ui(res, 0);

	for (i = 0; i < pub->lbits; i++) {

		mpz_powm(yi, y, powtwo[pub->lbits - 1 - i], prv->p);

		if (mpz_cmp_ui(yi, 1) == 0) {
			xi[i] = 0;
		} else {
			xi[i] = 1;

			mpz_mul(y, y, gvpvqp[i]);
			mpz_mod(y, y, prv->p);
		}
	}

	for (i = 0; i < pub->lbits; i++) {
		if (xi[i] == 1) {
			mpz_add(res, powtwo[i], res);
		}
	}

	mpz_clears(y, yi, NULL);
}

void dgk_freepubkey(dgk_pubkey_t* pub) {
	mpz_clears(pub->n, pub->u, pub->g, pub->h, NULL);
	free(pub);
}

void dgk_freeprvkey(dgk_prvkey_t* prv) {
	mpz_clears(prv->p, prv->q, prv->vp, prv->vq, prv->qinv, prv->pinv, prv->p_minusone, prv->q_minusone, NULL);
	free(prv);
}

void dgk_storekey(unsigned int modulusbits, unsigned int lbits, dgk_pubkey_t* pub, dgk_prvkey_t* prv) {
	FILE *fp;

	char smod[5];
	char slbit[4];
	char name[40] = "dkg_key_";
	const char* div = "_";
	const char* ext = ".bin";

	sprintf(smod, "%d", modulusbits);
	sprintf(slbit, "%d", lbits);

	strcat(name, smod);
	strcat(name, div);
	strcat(name, slbit);
	strcat(name, ext);

	printf("writing dgk key to %s\n", name);

	fp = fopen(name, "w");

	mpz_out_raw(fp, prv->p);
	mpz_out_raw(fp, prv->q);
	mpz_out_raw(fp, prv->vp);
	mpz_out_raw(fp, prv->vq);

	mpz_out_raw(fp, prv->pinv);
	mpz_out_raw(fp, prv->qinv);

	mpz_out_raw(fp, pub->n);
	mpz_out_raw(fp, pub->u);
	mpz_out_raw(fp, pub->g);
	mpz_out_raw(fp, pub->h);

	fclose(fp);
}

void dgk_readkey(unsigned int modulusbits, unsigned int lbits, dgk_pubkey_t** pub, dgk_prvkey_t** prv) {
	unsigned int i;

	mpz_t f1, tmp;

	mpz_inits(f1, tmp, NULL);

	char smod[5];
	char slbit[4];
	char name[40] = "dkg_key_";
	const char* div = "_";
	const char* ext = ".bin";

	sprintf(smod, "%d", modulusbits);
	sprintf(slbit, "%d", lbits);

	strcat(name, smod);
	strcat(name, div);
	strcat(name, slbit);
	strcat(name, ext);

//	printf("reading dgk key from %s\n", name);

	/* allocate the new key structures */
	*pub = (dgk_pubkey_t*) malloc(sizeof(dgk_pubkey_t));
	*prv = (dgk_prvkey_t*) malloc(sizeof(dgk_prvkey_t));

	FILE *fp;
	fp = fopen(name, "r");

	/* initialize our integers */
	mpz_init((*pub)->n);
	mpz_init((*pub)->u);
	mpz_init((*pub)->h);
	mpz_init((*pub)->g);

	mpz_init((*prv)->vp);
	mpz_init((*prv)->vq);
	mpz_init((*prv)->p);
	mpz_init((*prv)->q);

	mpz_init((*prv)->pinv);
	mpz_init((*prv)->qinv);

	mpz_init((*prv)->p_minusone);
	mpz_init((*prv)->q_minusone);

	mpz_inp_raw((*prv)->p, fp);
	mpz_inp_raw((*prv)->q, fp);
	mpz_inp_raw((*prv)->vp, fp);
	mpz_inp_raw((*prv)->vq, fp);
	mpz_inp_raw((*prv)->pinv, fp);
	mpz_inp_raw((*prv)->qinv, fp);

	mpz_inp_raw((*pub)->n, fp);
	mpz_inp_raw((*pub)->u, fp);
	mpz_inp_raw((*pub)->g, fp);
	mpz_inp_raw((*pub)->h, fp);

	fclose(fp);

	mpz_sub_ui((*prv)->p_minusone, (*prv)->p, 1);
	mpz_sub_ui((*prv)->q_minusone, (*prv)->q, 1);

	lbits = lbits * 2 + 2;

	(*pub)->bits = modulusbits;
	(*pub)->lbits = lbits;

	powtwo = (mpz_t*) malloc(sizeof(mpz_t) * lbits);
	gvpvqp = (mpz_t*) malloc(sizeof(mpz_t) * lbits);

	// array holding powers of two
	for (i = 0; i < lbits; i++) {
		mpz_init(powtwo[i]);
		mpz_setbit(powtwo[i], i);
	}

	mpz_powm(f1, (*pub)->g, (*prv)->vp, (*prv)->p); //gvpvq
	mpz_sub_ui(tmp, (*pub)->u, 1); // tmp1 = u - 1

	for (i = 0; i < lbits; i++) {
		mpz_init(gvpvqp[i]);
		mpz_powm(gvpvqp[i], f1, powtwo[i], (*prv)->p);
		mpz_powm(gvpvqp[i], gvpvqp[i], tmp, (*prv)->p);
	}

	/*
	 // debug output
	 gmp_printf("n  %Zd\n", (*pub)->n);
	 gmp_printf("u  %Zd\n", (*pub)->u);
	 gmp_printf("g  %Zd\n", (*pub)->g);
	 gmp_printf("h  %Zd\n", (*pub)->h);
	 gmp_printf("p  %Zd\n", (*prv)->p);
	 gmp_printf("q  %Zd\n", (*prv)->q);
	 gmp_printf("vp %Zd\n", (*prv)->vp);
	 gmp_printf("vq %Zd\n", (*prv)->vq);
	 gmp_printf("vpinv %Zd\n", (*prv)->pinv);
	 gmp_printf("vqinv %Zd\n", (*prv)->qinv);
	 */
}

void createKeys() {
	gmp_randstate_t rnd;

	gmp_randinit_default(rnd);
	gmp_randseed_ui(rnd, rand());

	dgk_pubkey_t * pub;
	dgk_prvkey_t * prv;

	mpz_t msg, ct, msg2;

	mpz_inits(msg, ct, msg2, NULL);

	for (unsigned int n = 1024; n <= 3072; n += 1024) {
		for (unsigned int l = 8; l <= 64; l *= 2) {

			// choose either keygen or readkey
//			dgk_keygen(n, l, &pub, &prv); //uncomment to acutally create keys
			dgk_readkey(n, l, &pub, &prv); //only read from file

			int no_error = 1;

			if (l < 16) {
				int maxit = 1 << l;
				for (int i = 0; i < maxit; i++) {
					mpz_set_ui(msg, i);
					dgk_encrypt_plain(ct, pub, msg, rnd);
					dgk_decrypt(msg2, pub, prv, ct);

					if (mpz_cmp(msg, msg2)) {
						//					printf("ERROR: \n");
						//
						//					gmp_printf("msg  %Zd\n", msg);
						//					gmp_printf("ct   %Zd\n", ct);
						//					gmp_printf("msg2 %Zd\n", msg2);
						//
						//					gmp_printf("n  %Zd\n", pub->n);
						//					gmp_printf("u  %Zd\n", pub->u);
						//					gmp_printf("g  %Zd\n", pub->g);
						//					gmp_printf("h  %Zd\n", pub->h);
						//					gmp_printf("p  %Zd\n", prv->p);
						//					gmp_printf("q  %Zd\n", prv->q);
						//					gmp_printf("vp %Zd\n", prv->vp);
						//					gmp_printf("vq %Zd\n", prv->vq);
						printf(".");
						i = maxit;
						no_error = 0;
					}
				}
			} else {
				for (int i = 0; i < KEYTEST_ITERATIONS; i++) {

					if (i > 3) {
						mpz_urandomb(msg, rnd, l);
					}
					// test some corner cases first: 0, 1, 2^l-1, 2^l-2. After that random numbers.
					else if (i == 0)
						mpz_set_ui(msg, 0);
					else if (i == 1)
						mpz_set_ui(msg, 1);
					else if (i == 2) {
						mpz_set_ui(msg, 0);
						mpz_setbit(msg, l);
						mpz_sub_ui(msg, msg, 1);
					} else if (i == 3) {
						mpz_sub_ui(msg, msg, 1);
					}

					dgk_encrypt_plain(ct, pub, msg, rnd);
					dgk_decrypt(msg2, pub, prv, ct);

					if (mpz_cmp(msg, msg2)) {
						// Error: decrypted message is different from encrypted message. We have to start again.
						//					printf("ERROR: \n");
						//
						//					gmp_printf("msg  %Zd\n", msg);
						//					gmp_printf("ct   %Zd\n", ct);
						//					gmp_printf("msg2 %Zd\n", msg2);
						//
						//					gmp_printf("n  %Zd\n", pub->n);
						//					gmp_printf("u  %Zd\n", pub->u);
						//					gmp_printf("g  %Zd\n", pub->g);
						//					gmp_printf("h  %Zd\n", pub->h);
						//					gmp_printf("p  %Zd\n", prv->p);
						//					gmp_printf("q  %Zd\n", prv->q);
						//					gmp_printf("vp %Zd\n", prv->vp);
						//					gmp_printf("vq %Zd\n", prv->vq);
						printf(".");
						break;
						no_error = 0;
					}
				}
			}
			if (no_error) {
				dgk_storekey(n, l, pub, prv);
			} else {
				if (l > 4) { // re-do last iteration
					l /= 2;
				}
			}
		}
	}
}

void test_encdec() {
	gmp_randstate_t rnd;

	gmp_randinit_default(rnd);
	gmp_randseed_ui(rnd, rand());

	dgk_pubkey_t * pub;
	dgk_prvkey_t * prv;

	mpz_t a0, a1, b0, b1, c0, c1, r, d, a0c, b0c, rc, tmp0, tmp1;

	mpz_inits(a0, a1, b0, b1, c0, c1, r, d, a0c, b0c, rc, tmp0, tmp1, NULL);

	unsigned int l = 8;
	unsigned int nbit = 1024;

	//choose either keygen or readkey
	//dgk_keygen(nbit, l, &pub, &prv);
	dgk_readkey(nbit, l, &pub, &prv);

	mpz_urandomb(a0, rnd, l);

	dgk_encrypt_crt(a0c, pub, prv, a0, rnd); //encrypt a0

	dgk_decrypt(b0, pub, prv, a0c);

	if (mpz_cmp(a0, b0) == 0) {
		printf("fine\n");
	} else {
		printf("ERR :(\n");
		gmp_printf("%Zd, %Zd", a0, b0);
	}

	dgk_encrypt_plain(a0c, pub, a0, rnd);
	dgk_decrypt(b0, pub, prv, a0c);

	if (mpz_cmp(a0, b0) == 0) {
		printf("fine\n");
	} else {
		printf("ERR :(\n");
		gmp_printf("%Zd, %Zd", a0, b0);
	}
}

void test_sharing() {
	gmp_randstate_t rnd;

	gmp_randinit_default(rnd);
	gmp_randseed_ui(rnd, rand());

	dgk_pubkey_t * pub;
	dgk_prvkey_t * prv;

	mpz_t a0, a1, b0, b1, c0, c1, r, d, a0c, b0c, rc, tmp0, tmp1;

	mpz_inits(a0, a1, b0, b1, c0, c1, r, d, a0c, b0c, rc, tmp0, tmp1, NULL);

	unsigned int l = 8;
	unsigned int nbit = 1024;

	//choose either keygen or readkey
	//dgk_keygen(nbit, l, &pub, &prv);
	dgk_readkey(nbit, l, &pub, &prv);

	// choose random a and b shares, l bits long
	mpz_urandomb(a0, rnd, l);
	mpz_urandomb(b0, rnd, l);
	mpz_urandomb(a1, rnd, l);
	mpz_urandomb(b1, rnd, l);

	gmp_printf("a0,b0: %Zd %Zd \n", a0, b0);
	gmp_printf("a1,b1: %Zd %Zd \n", a1, b1);

	// choose random r for masking
	mpz_urandomb(r, rnd, 2 * l + 2);

	dgk_encrypt_plain(a0c, pub, a0, rnd); //encrypt a0
	dgk_encrypt_plain(b0c, pub, b0, rnd); //encrypt b0
	dgk_encrypt_plain(rc, pub, r, rnd); //encrypt r

	mpz_mul(c1, a1, b1);
	mpz_mod_2exp(c1, c1, l);
	mpz_sub(c1, c1, r); // c1 = a1*b1 - r
	mpz_mod_2exp(c1, c1, l); // % l (stay within plaintext space)

	// homomorphic multiplication
	mpz_powm(a0c, a0c, b1, pub->n);
	mpz_powm(b0c, b0c, a1, pub->n);

	// test from here
	dgk_decrypt(d, pub, prv, a0c);
	gmp_printf("---test shares---\ndec a0*b1= %Zd\n", d);

	mpz_mul(tmp0, b1, a0);
	gmp_printf("a0*b1=     %Zd\n", tmp0);

	dgk_decrypt(d, pub, prv, b0c);
	gmp_printf("dec a1*b0= %Zd\n", d);

	mpz_mul(tmp1, b0, a1);
	gmp_printf("a1*b0=     %Zd\n---test shares---\n", tmp1);
	// test till here

	mpz_mul(a0c, a0c, b0c); // multiply [a0]^b1 and [b0]^a1 (homomorphic addition)
	mpz_mod(a0c, a0c, pub->n); // product % n (stay within ciphertext space)

	// test from here
	dgk_decrypt(d, pub, prv, a0c); // decrypt ciphertext (sum of products a0c, yet no r)
	gmp_printf("dec 4x= %Zd\n", d);

	mpz_add(tmp0, tmp0, tmp1); // add plaintext products, should be equal to d
	gmp_printf("4x=     %Zd\n", tmp0);

	mpz_add(tmp0, tmp0, r); // plaintext add r
	mpz_mod_2exp(tmp1, tmp0, l); // mod l
	gmp_printf("4x + r= %Zd = %Zd (mod l)\n", tmp0, tmp1);
	// test till here

	mpz_mul(a0c, a0c, rc); // homomorphic addition of r
	mpz_mod(a0c, a0c, pub->n); // product % n

	dgk_decrypt(d, pub, prv, a0c); // decrypt masked sum+r

	mpz_mul(c0, a0, b0); // c0 = a0 * b0
	mpz_mod_2exp(c0, c0, l); // c0 = c0 % 2^l
	mpz_add(c0, c0, d); // c0 = c0 + d
	mpz_mod_2exp(c0, c0, l); // c0 = c0 % 2^l

	gmp_printf("%Zd %Zd %Zd\n", a0, b0, c0);
	gmp_printf("%Zd %Zd %Zd\n", a1, b1, c1);
	gmp_printf("%Zd %Zd\n", r, d);

	// test if MT is valid: (a0+a1) * (b0+b1) = c0+c1  [mod l]
	mpz_add(a0, a0, a1);
	mpz_add(b0, b0, b1);
	mpz_mul(a0, a0, b0);
	mpz_add(c0, c0, c1);

	mpz_mod_2exp(c0, c0, l);
	mpz_mod_2exp(a0, a0, l);

	if (mpz_cmp(a0, c0) == 0) {
		printf("fine\n");
	} else {
		printf("ERR :(\n");
	}
}

/**
 * uncomment the following main for direct testing
 */
//int main(){
//	srand (time(NULL)^clock());
//
////	createKeys();
////	test_encdec();
//	test_sharing();
//	printf("END");
//
//	return 0;
//}
//
