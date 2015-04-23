/**
 \file 		mb.c
 \author 	Marina Blanton
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2015 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
			it under the terms of the GNU Affero General Public License as published
			by the Free Software Foundation, either version 3 of the License, or
			(at your option) any later version.
			This program is distributed in the hope that it will be useful,
			but WITHOUT ANY WARRANTY; without even the implied warranty of
			MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
			GNU Affero General Public License for more details.
			You should have received a copy of the GNU Affero General Public License
			along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		extracted from program for private comparison of iris codes from 2010
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <miracl.h>
#include <time.h>
#include <sys/time.h>

#define T	160
#define K	1024
#define L	21 // bitlength of plaintext

static big g, h, n, u, vp, vq, p, q, f1, f2, gvp, r, one;
static csprng rng;
static big pow2[L];
static big gvpp[L];
static miracl *mip;

void enc(big m, big res);
void dec(big c, big res);
void create_key();
void store_key();
void read_key();

char number[200];

void printnum(big n) {
	int len, i;
	len = big_to_bytes(200, n, number, FALSE);
	printf("%d %d ", numdig(n), len);
	for (i = 0; i < len; i++) {
		printf("%02x", number[i] & 0xff);
	}
	printf("\n");
}

// assumes one argument, which is a random string
int main(int argc, char *argv[]) {
	big tmp2, phin, tmp;
	long seed;
	struct timeval time1, time2;
	int i;

	mip = mirsys(K, 2);
	mip->NTRY = 200;

	ctime(&seed);
	irand(seed);
	strong_init(&rng, strlen(argv[1]), argv[1], seed);
	one = mirvar(1);
	phin = mirvar(0);
	tmp = mirvar(0);
	tmp2 = mirvar(0);

	create_key();
	store_key();
	read_key();

	// gvpp[i] contains gvp raised to powers of 2 and then -1
	gvp = mirvar(0);
	powmod(g, vp, p, gvp);

	pow2[0] = mirvar(1);
	pow2[1] = mirvar(2);
	for (i = 2; i < L; i++) {
		pow2[i] = mirvar(0);
		multiply(pow2[i - 1], pow2[1], pow2[i]);
	}

	for (i = 0; i < L; i++) {
		gvpp[i] = mirvar(0);
		powmod(gvp, pow2[i], p, gvpp[i]);
		powmod(gvpp[i], tmp2, p, gvpp[i]);
	}

	// can call encryption/decryption here by specifying two big numbers 
	// (input and ouput) for each function

	return 0;
}

/*  encryption routine */
void enc(big m, big res) {
	big tmp = mirvar(0);

	strong_bigdig(&rng, 2.5 * T, 2, r);
	powmod(h, r, n, res);
	powmod(g, m, n, tmp);
	mad(res, tmp, tmp, n, n, res);
}

/* decryption routine */
void dec(big c, big res) {
	int i, xi[L];
	big y = mirvar(0);
	big yi = mirvar(0);

	powmod(c, vp, p, y);
	// perform pohlig-hellman
	for (i = 0; i < L; i++) {
		power(y, pow2[L - 1 - i], p, yi);
		if (compare(yi, one) == 0) {
			xi[i] = 0;
		} else {
			xi[i] = 1;
			mad(gvpp[i], y, y, p, p, y);
		}
	}

	// assemble result: print to a string and call bytes_to_big
	for (i = 1; i < L; i++) {
		if (xi[i] == 1)
			xi[0] += pow2[i];
	}
	convert(xi[0], res);
}

void create_key() {
	BOOL found;
	big tmp, tmp1, xp, xq;
	long count = 0;
	int modsize;

	// 1) key generation 
	// choose v_p, v_q, and u
	found = FALSE;
	vp = mirvar(0);
	while (!found) {
		strong_bigdig(&rng, T, 2, vp);
		found = isprime(vp);
		count++;
	}
	printf("number of trials for vp: %ld\n", count);

	count = 0;
	found = FALSE;
	vq = mirvar(0);
	while (!found) {
		strong_bigdig(&rng, T, 2, vq);
		found = isprime(vq);
		count++;
	}
	printf("number of trials for vq: %ld\n", count);

	u = mirvar(0);
	expb2(L, u);

	// create p and q
	count = 0;
	found = FALSE;
	p = mirvar(0);
	f1 = mirvar(0);
	while (!found) {
		strong_bigdig(&rng, K / 2 - T - L, 2, f1);
		found = isprime(f1);
		if (found) {
			multiply(vp, u, p);
			multiply(p, f1, p);
			incr(p, 1, p);
			found = isprime(p);
		}
		count++;
	}
	printf("number of trials for p: %ld\n", count);

	count = 0;
	found = FALSE;
	q = mirvar(0);
	f2 = mirvar(0);
	while (!found) {
		strong_bigdig(&rng, K / 2 - T - L + 1, 2, f2);
		found = isprime(f2);
		count++;
		if (found) {
			multiply(vq, u, q);
			multiply(q, f2, q);
			incr(q, 1, q);
			found = isprime(q);
		}
	}
	printf("number of trials for q: %ld\n", count);

	// compute n=p*q and generators g and h
	n = mirvar(0);
	multiply(p, q, n);
	modsize = numdig(n);

	tmp = mirvar(0);
	tmp1 = mirvar(0);
	found = FALSE;
	g = mirvar(0);

	// choose a number from Z^*_p and check its order
	count = 0;
	xp = mirvar(0);
	big exp1 = mirvar(0);
	expb2(L - 1, exp1);
	multiply(exp1, vp, exp1);
	multiply(exp1, f1, exp1);
	big exp2 = mirvar(0);
	multiply(vp, u, exp2);
	big exp3 = mirvar(0);
	multiply(f1, u, exp3);
	while (!found) {
		strong_bigdig(&rng, numdig(p), 2, xp);
		if (compare(xp, p) < 0)
			found = TRUE;
		if (found) {
			powmod(xp, exp1, p, tmp);
			if (compare(tmp, one) == 0) {
				found = FALSE;
			} else {
				powmod(xp, exp2, p, tmp);
				if (compare(tmp, one) == 0) {
					found = FALSE;
				} else {
					powmod(xp, exp3, p, tmp);
					if (compare(tmp, one) == 0) {
						found = FALSE;
					}
				}
			}
			count++;
		}
	}
	printf("number of trials for xp: %ld\n", count);

	found = FALSE;
	// choose a number from Z^*_q and check its order
	xq = mirvar(0);
	expb2(L - 1, exp1);
	multiply(exp1, vq, exp1);
	multiply(exp1, f2, exp1);
	multiply(vq, u, exp2);
	multiply(f2, u, exp3);
	count = 0;
	while (!found) {
		strong_bigdig(&rng, numdig(q), 2, xq);
		if (compare(xq, q) < 0)
			found = TRUE;

		if (found) {
			powmod(xq, exp1, q, tmp);
			if (compare(tmp, one) == 0) {
				found = FALSE;
			} else {
				powmod(xq, exp2, q, tmp);
				if (compare(tmp, one) == 0) {
					found = FALSE;
				} else {
					powmod(xq, exp3, q, tmp);
					if (compare(tmp, one) == 0) {
						found = FALSE;
					}
				}
			}
			count++;
			if (count == 100)
				found = TRUE;
		}
	}
	printf("number of trials for xq: %ld\n", count);

	// compute CRT: g = xp*q*(q^{-1} mod p) + xq*p*(p^{-1} mod q) mod n
	xgcd(q, p, tmp, tmp, tmp);
	multiply(q, tmp, tmp);
	mad(xp, tmp, tmp, n, n, tmp);
	xgcd(p, q, tmp1, tmp1, tmp1);
	multiply(p, tmp1, tmp1);
	mad(xq, tmp1, tmp1, n, n, tmp1);
	mad(xp, one, xq, n, n, g);
	multiply(f1, f2, tmp);
	powmod(g, tmp, n, g);

	found = FALSE;
	h = mirvar(0);
	while (!found) {
		strong_bigdig(&rng, modsize, 2, h);
		if (compare(h, n) < 0)
			found = TRUE;
	}
	multiply(f1, f2, tmp);
	multiply(tmp, u, tmp);
	powmod(h, tmp, n, h);

}

void store_key() {
	/* the elements of the key are stored in a file one value per line in the 
	 following order: p, q, n, g, h, u, vp, f1, vq, f2 */
	FILE *fp;
	fp = fopen("new-key.txt", "w");
	mip->IOBASE = 16;
	cotnum(p, fp);
	cotnum(q, fp);
	cotnum(n, fp);
	cotnum(g, fp);
	cotnum(h, fp);
	cotnum(u, fp);
	cotnum(vp, fp);
	cotnum(f1, fp);
	cotnum(vq, fp);
	cotnum(f2, fp);
	fclose(fp);
}

void read_key() {
	FILE *fp;
	fp = fopen("new-key.txt", "r");
	mip->IOBASE = 16;
	p = mirvar(0);
	q = mirvar(0);
	n = mirvar(0);
	g = mirvar(0);
	h = mirvar(0);
	u = mirvar(0);
	vp = mirvar(0);
	f1 = mirvar(0);
	vq = mirvar(0);
	f2 = mirvar(0);
	cinnum(p, fp);
	cinnum(q, fp);
	cinnum(n, fp);
	cinnum(g, fp);
	cinnum(h, fp);
	cinnum(u, fp);
	cinnum(vp, fp);
	cinnum(f1, fp);
	cinnum(vq, fp);
	cinnum(f2, fp);
	fclose(fp);
}
