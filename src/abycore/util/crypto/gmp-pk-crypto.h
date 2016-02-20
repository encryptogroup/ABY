/**
 \file 		gmp-pk-crypto.h
 \author 	michael.zohner@ec-spride.de
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
 \brief		Class with finite-field-cryptography operations (using the GMP library)
 */

#ifndef GMP_PK_CRYPTO_H_
#define GMP_PK_CRYPTO_H_

#include "pk-crypto.h"
#include <gmp.h>

class prime_field;
class gmp_fe;
class gmp_num;
class gmp_brickexp;

#define fe2mpz(fieldele) (((gmp_fe*) (fieldele))->get_val())
#define num2mpz(number) (((gmp_num*) (number))->get_val())

class prime_field: public pk_crypto {
public:
	prime_field(seclvl sp, uint8_t* seed) :
			pk_crypto(sp, seed) {
		init(sp, seed);
	}
	;
	~prime_field();

	num* get_num();
	num* get_rnd_num(uint32_t bitlen = 0);
	fe* get_fe();
	fe* get_rnd_fe(uint32_t bitlen);
	fe* get_generator();
	fe* get_rnd_generator();
	num* get_order();

	mpz_t* get_p();
	uint32_t get_size();
	brickexp* get_brick(fe* gen);

	uint32_t num_byte_size() {
		return ceil_divide(secparam.ifcbits, 8);
	}
	uint32_t get_field_size() {
		return secparam.ifcbits;
	}
	;

protected:
	void init(seclvl sp, uint8_t* seed);
private:
	mpz_t p;
	mpz_t g;
	mpz_t q;
	gmp_randstate_t rnd_state;
};

class gmp_fe: public fe {
public:
	gmp_fe(prime_field* fld);
	gmp_fe(prime_field* fld, mpz_t src);
	~gmp_fe();
	void set(fe* src);
	mpz_t* get_val();

	void set_mul(fe* a, fe* b);
	void set_pow(fe* b, num* e);
	void set_div(fe* a, fe* b);
	void set_double_pow_mul(fe* b1, num* e1, fe* b2, num* e2);
	void export_to_bytes(uint8_t* buf);
	void import_from_bytes(uint8_t* buf);
	void sample_fe_from_bytes(uint8_t* buf, uint32_t bytelen);
	bool eq(fe* a);
	void print() {
		cout << val << endl;
	}
	;

private:
	void init() {
		mpz_init(val);
	}
	;
	mpz_t val;
	prime_field* field;

};

class gmp_num: public num {
public:
	gmp_num(prime_field* fld);
	gmp_num(prime_field* fld, mpz_t src);
	~gmp_num();
	void set(num* src);
	void set_si(int32_t src);
	void set_add(num* a, num* b);
	void set_sub(num* a, num* b);
	void set_mul(num* a, num* b);
	void mod(num* mod);
	void set_mul_mod(num* a, num* b, num* modulus) ;

	mpz_t* get_val();

	void export_to_bytes(uint8_t* buf, uint32_t field_size);
	void import_from_bytes(uint8_t* buf, uint32_t field_size);
	void set_rnd(uint32_t bits);
	void print() {
		cout << val << endl;
	}
	;
private:
	mpz_t val;
	prime_field* field;
};

class gmp_brickexp: public brickexp {
public:
	gmp_brickexp(fe* g, prime_field* pfield) {
		init(g, pfield);
	}
	;
	~gmp_brickexp();

	void pow(fe* result, num* e);
	void init(fe* g, prime_field* pfield);

private:
	uint32_t m_numberOfElements;
	mpz_t* m_table;
	prime_field* field;
};

// mpz_export does not fill leading zeros, thus a prepending of leading 0s is required
void mpz_export_padded(uint8_t* pBufIdx, uint32_t field_size, mpz_t to_export);

#endif /* GMP_PK_CRYPTO_H_ */
