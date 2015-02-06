/**
 \file 		pk-crypto.h
 \author 	michael.zohner@ec-spride.de
 \copyright __________________
 \brief		Virtual class for public-key operations
 */

#ifndef PK_CRYPTO_H_
#define PK_CRYPTO_H_

#include "../typedefs.h"
#include "../constants.h"

class pk_crypto;
class num;
class fe;
class brickexp;

class pk_crypto {
public:
	pk_crypto(seclvl sp, uint8_t* seed) {
	}
	;
	~pk_crypto() {
	}
	;
	virtual num* get_num() = 0;
	virtual num* get_rnd_num(uint32_t bitlen = 0) = 0;
	virtual fe* get_fe() = 0;
	virtual fe* get_rnd_fe(uint32_t bitlen) = 0;
	virtual fe* get_generator() = 0;
	virtual fe* get_rnd_generator() = 0;
	virtual uint32_t num_byte_size() = 0;
	uint32_t fe_byte_size() {
		return fe_bytelen;
	}
	;
	virtual uint32_t get_field_size() =0;
	virtual brickexp* get_brick(fe* gen) = 0;

protected:
	virtual void init(seclvl secparam, uint8_t* seed) = 0;
	uint32_t fe_bytelen;
	seclvl secparam;
};

//class number
class num {
public:
	num() {
	}
	;
	~num() {
	}
	;
	virtual void set(num* src) = 0;
	virtual void set_si(int32_t src) = 0;
	virtual void set_add(num* a, num* b) = 0;
	virtual void set_mul(num* a, num* b) = 0;
	virtual void export_to_bytes(uint8_t* buf, uint32_t field_size) = 0;
	virtual void import_from_bytes(uint8_t* buf, uint32_t field_size) = 0;
	virtual void print() = 0;
};

//class field_element
class fe {
public:
	fe() {
	}
	;
	~fe() {
	}
	;
	virtual void set(fe* src) = 0;
	virtual void set_mul(fe* a, fe* b) = 0;
	virtual void set_pow(fe* b, num* e) = 0;
	virtual void set_div(fe* a, fe* b) = 0;
	virtual void set_double_pow_mul(fe* b1, num* e1, fe* b2, num* e2) = 0;
	virtual void export_to_bytes(uint8_t* buf) = 0;
	virtual void import_from_bytes(uint8_t* buf) = 0;
	virtual void sample_fe_from_bytes(uint8_t* buf, uint32_t bytelen) = 0;
	virtual void print() = 0;

protected:
	virtual void init() = 0;
};

class brickexp {
public:
	brickexp() {
	}
	;
	~brickexp() {
	}
	;

	virtual void pow(fe* result, num* e) = 0;
};

#endif /* PK_CRYPTO_H_ */
