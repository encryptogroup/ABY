/**
 \file 		powmod.h
 \author 	daniel.demmler@ec-spride.de
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
 \brief		Powmod Implementation
 */

#ifndef _POWMOD_H_
#define _POWMOD_H_

#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>

extern mpz_t* m_table_g;
extern mpz_t* m_table_h;
extern mpz_t* m_prod;
extern mpz_t m_mod;
extern int m_numberOfElements_g;
extern int m_numberOfElements_h;

/**
 * initialize fixed base multiplication for a given base and a desired exponent bit size
 * identical functionality for either g or h
 */
void fbpowmod_init_g(const mpz_t base, const mpz_t mod, const int bitsize);
void fbpowmod_init_h(const mpz_t base, const mpz_t mod, const int bitsize);

/**
 * fixed-base multiplication
 * requires pre-computed table, created with fbpowmod_init_*
 */
void fbpowmod_g(mpz_t result, const mpz_t exp);
void fbpowmod_h(mpz_t result, const mpz_t exp);

/**
 * fixed-base double base encryption
 * requires pre-computed product with fbdbpowmod_init
 */
void fbdbpowmod(mpz_t ret, const mpz_t e1, const mpz_t e2);
void fbdbpowmod_init(const mpz_t b1, const mpz_t b2, const mpz_t mod, const int bitsize);

/**
 * double-base exponentiation ret = b1^e1*b2^e2
 */
void dbpowmod(mpz_t ret, const mpz_t b1, const mpz_t e1, const mpz_t b2, const mpz_t e2, const mpz_t mod);

#endif
