/**
 \file 		powmod.cpp
 \author 	Daniel Demmler
 \copyright __________________
 \brief		PowMod Implementation
 */

#include "powmod.h"

#define POWMOD_DEBUG 0

mpz_t* m_table_g;
mpz_t* m_table_h;
mpz_t* m_prod;
mpz_t m_mod;
int m_numberOfElements_g, m_numberOfElements_h;

void fbpowmod_init_g(const mpz_t base, const mpz_t mod, const int bitsize) {
	int i;
	unsigned u;
	m_numberOfElements_g = bitsize;
	mpz_init(m_mod);
	mpz_set(m_mod, mod);
	m_table_g = (mpz_t*) malloc(sizeof(mpz_t) * bitsize);
	for (i = 0; i < bitsize; i++) {
		mpz_init(m_table_g[i]);
	}

	mpz_set(m_table_g[0], base);
	for (u = 1; u < bitsize; u++) {
		mpz_mul(m_table_g[u], m_table_g[u - 1], m_table_g[u - 1]);
		mpz_mod(m_table_g[u], m_table_g[u], mod);
	}
}

void fbpowmod_init_h(const mpz_t base, const mpz_t mod, const int bitsize) {
	int i;
	unsigned u;
	m_numberOfElements_h = bitsize;
	mpz_init(m_mod);
	mpz_set(m_mod, mod);
	m_table_h = (mpz_t*) malloc(sizeof(mpz_t) * bitsize);
	for (i = 0; i < bitsize; i++) {
		mpz_init(m_table_h[i]);
	}

	mpz_set(m_table_h[0], base);
	for (u = 1; u < bitsize; u++) {
		mpz_mul(m_table_h[u], m_table_h[u - 1], m_table_h[u - 1]);
		mpz_mod(m_table_h[u], m_table_h[u], mod);
	}
}

void fbpowmod_g(mpz_t result, const mpz_t exp) {
	unsigned u;
	unsigned top = mpz_sizeinbase(exp, 2);
	if (top <= m_numberOfElements_g) {
		mpz_set_ui(result, 1);

		for (u = 0; u < top; u++) {
			if (mpz_tstbit(exp, u)) {
				mpz_mul(result, result, m_table_g[u]);
				mpz_mod(result, result, m_mod);
			}
		}
	} else {
		printf("(g) Exponent too big for pre-computed fixed-base powmod! %d %d\n", top, m_numberOfElements_g);
	}
}

void fbpowmod_h(mpz_t result, const mpz_t exp) {
	unsigned u;
	unsigned top = mpz_sizeinbase(exp, 2);
	if (top <= m_numberOfElements_h) {
		mpz_set_ui(result, 1);

		for (u = 0; u < top; u++) {
			if (mpz_tstbit(exp, u)) {
				mpz_mul(result, result, m_table_h[u]);
				mpz_mod(result, result, m_mod);
			}
		}
	} else {
		printf("Exponent too big for pre-computed fixed-base powmod! %d %d\n", top, m_numberOfElements_h);
	}
}

void dbpowmod(mpz_t ret, const mpz_t b1, const mpz_t e1, const mpz_t b2, const mpz_t e2, const mpz_t mod) {
	int i;
	unsigned char index;
	mpz_t prod[3];

	int size = (mpz_cmp(e1, e2) > 0) ? mpz_sizeinbase(e1, 2) : mpz_sizeinbase(e2, 2);

#if POWMOD_DEBUG
	printf("size: %d\n", size);
#endif

	mpz_init_set(prod[0], b1);
	mpz_init_set(prod[1], b2);
	mpz_init(prod[2]);

	mpz_mul(prod[2], b1, b2);
	mpz_mod(prod[2], prod[2], mod);

	mpz_set_ui(ret, 1);
	for (i = size - 1; i >= 0; i--) {
		index = (mpz_tstbit(e2, i) << 1) + mpz_tstbit(e1, i);

#if POWMOD_DEBUG
		gmp_printf("%d | %Zd", index, ret);
#endif

		mpz_mul(ret, ret, ret);
		mpz_mod(ret, ret, mod);

#if POWMOD_DEBUG
		gmp_printf(" - sq:%Zd", ret);
#endif

		if (index) {
			mpz_mul(ret, prod[index - 1], ret);
			mpz_mod(ret, ret, mod);
		}

#if POWMOD_DEBUG
		gmp_printf(" -  end:%Zd\n", ret);
#endif
	}

	mpz_clears(prod[0], prod[1], prod[2], NULL);
}

void fbdbpowmod_init(const mpz_t b1, const mpz_t b2, const mpz_t mod, const int bitsize) {

	mpz_init(m_mod);
	mpz_set(m_mod, mod);

	m_prod = (mpz_t*) malloc(sizeof(mpz_t) * 3);

	mpz_init_set(m_prod[0], b1);
	mpz_init_set(m_prod[1], b2);
	mpz_init(m_prod[2]);
	mpz_mul(m_prod[2], b1, b2);
	mpz_mod(m_prod[2], m_prod[2], mod);
}

void fbdbpowmod(mpz_t ret, const mpz_t e1, const mpz_t e2) {

	int i;
	unsigned char index;

	int size = (mpz_cmp(e1, e2) > 0) ? mpz_sizeinbase(e1, 2) : mpz_sizeinbase(e2, 2);

	mpz_set_ui(ret, 1);
	for (i = size - 1; i >= 0; i--) {
		index = (mpz_tstbit(e2, i) << 1) + mpz_tstbit(e1, i);

		mpz_mul(ret, ret, ret);
		mpz_mod(ret, ret, m_mod);

		if (index) {
			mpz_mul(ret, m_prod[index - 1], ret);
			mpz_mod(ret, ret, m_mod);
		}
	}
}
