/**
 \file 		ecc-pk-crypto.cpp
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
 \brief		Implementation of ECC routines
 */

#include "ecc-pk-crypto.h"

char *ecx163 = (char *) "2fe13c0537bbc11acaa07d793de4e6d5e5c94eee8";
char *ecy163 = (char *) "289070fb05d38ff58321f2e800536d538ccdaa3d9";

char *ecx233 = (char *) "17232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126";
char *ecy233 = (char *) "1db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3";

char *ecx283 = (char *) "503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac2458492836";
char *ecy283 = (char *) "1ccda380f1c9e318d90f95d07e5426fe87e45c0e8184698e45962364e34116177dd2259";

void ecc_field::init(seclvl sp, uint8_t* seed) {

	miracl *mip = mirsys(sp.ecckcbits, 2);
	fparams = (ecc_fparams*) malloc(sizeof(ecc_fparams));
	secparam = sp;

	char *ecp = NULL, *ecb = NULL, *ecx = ecx163, *ecy = ecy163;
	fparams->BB = new Big();
	fparams->BA = new Big();
	fparams->BP = new Big();

	if (secparam.ecckcbits == ST.ecckcbits) {
		ecx = ecx163;
		ecy = ecy163;
		fparams->m = 163;
		fparams->a = 7;
		fparams->b = 6;
		fparams->c = 3;
		*fparams->BA = 1;
		fparams->secparam = ST.ecckcbits;
	} else if (secparam.ecckcbits == MT.ecckcbits) {
		ecx = ecx233;
		ecy = ecy233;
		fparams->m = 233;
		fparams->a = 74;
		fparams->b = 0;
		fparams->c = 0;
		*fparams->BA = 0;
		fparams->secparam = MT.ecckcbits;
	} else if (secparam.ecckcbits == LT.ecckcbits) {
		ecx = ecx283;
		ecy = ecy283;
		fparams->m = 283;
		fparams->a = 12;
		fparams->b = 7;
		fparams->c = 5;
		*fparams->BA = 0;
		fparams->secparam = LT.ecckcbits;
	} else { //Long term security
		ecx = ecx283;
		ecy = ecy283;
		fparams->m = 283;
		fparams->a = 12;
		fparams->b = 7;
		fparams->c = 5;
		*fparams->BA = 0;
		fparams->secparam = LT.ecckcbits;
	}

	//seed the miracl rnd generator
	irand((long) (*seed));

	//Change the base to read in the parameters
	mip->IOBASE = 16;
	*fparams->BB = 1;

	ecurve2_init(fparams->m, fparams->a, fparams->b, fparams->c, fparams->BA->getbig(), fparams->BB->getbig(), false, MR_BEST);

	fparams->X = new Big();
	fparams->Y = new Big();
	*fparams->X = ecx;
	*fparams->Y = ecy;

	//For ECC, a coordinate is transferred as well as a 1/-1
	fe_bytelen = ceil_divide(secparam.ecckcbits,8) + 1;

	mip->IOBASE = 16;
}

ecc_field::~ecc_field() {
	delete fparams->Y;
	delete fparams->X;
	delete fparams->BA;
	delete fparams->BB;
	delete fparams->BP;

	free(fparams);

	mirexit();
}

num* ecc_field::get_num() {
	return new ecc_num(this);
}

num* ecc_field::get_rnd_num(uint32_t bitlen) {
	Big ele;
	if (bitlen == 0)
		bitlen = secparam.ecckcbits;
	ele = rand(bitlen, 2);
	return new ecc_num(this, &ele);
}
fe* ecc_field::get_fe() {
	return new ecc_fe(this);
}

fe* ecc_field::get_rnd_fe(uint32_t bitlen) {
	return sample_random_point();
}

fe* ecc_field::get_generator() {
	EC2 g = EC2(*fparams->X, *fparams->Y);
	return new ecc_fe(this, &g);
}
fe* ecc_field::get_rnd_generator() {
	return sample_random_point();
}
brickexp* ecc_field::get_brick(fe* gen) {
	return new ecc_brickexp(gen, fparams);
}
uint32_t ecc_field::get_size() {
	return secparam.ecckcbits;
}

fe* ecc_field::sample_random_point() {
	Big bigtmp;
	EC2 point;
	uint32_t itmp = rand() % 2;
	do {
		bigtmp = rand(secparam.symbits, 2);
		point = EC2(bigtmp, itmp);
	} while (point_at_infinity(point.get_point()));
	return new ecc_fe(this, &point);
}

ecc_fe::ecc_fe(ecc_field* fld) {
	field = fld;
	init();
}

ecc_fe::ecc_fe(ecc_field* fld, EC2* src) {
	field = fld;
	init();
	*val = *src;
}
ecc_fe::~ecc_fe() {
	delete val;
}

void ecc_fe::set(fe* src) {
	*val = *fe2ec2(src);
}
EC2* ecc_fe::get_val() {
	return val;
}

void ecc_fe::set_mul(fe* a, fe* b) {
	set(a);
	(*val) += (*fe2ec2(b));
}

void ecc_fe::set_pow(fe* b, num* e) {
	set(b);
	(*val) *= (*num2Big(e));
}

void ecc_fe::set_div(fe* a, fe* b) {
	set(a);
	(*val) -= (*fe2ec2(b));
}

void ecc_fe::set_double_pow_mul(fe* b1, num* e1, fe* b2, num* e2) {
	ecurve2_mult2(num2Big(e1)->getbig(), fe2ec2(b1)->get_point(), num2Big(e2)->getbig(), fe2ec2(b2)->get_point(), val->get_point());
}

void ecc_fe::import_from_bytes(uint8_t* buf) {
	byte_to_point(val, field->fe_byte_size(), buf);
}
//export and pad all leading zeros
void ecc_fe::export_to_bytes(uint8_t* buf) {
	point_to_byte(buf, field->fe_byte_size(), val);
}

void ecc_fe::sample_fe_from_bytes(uint8_t* buf, uint32_t bytelen) {
	EC2 point;
	Big bigtmp;
	uint8_t* tmpbuf = (uint8_t*) calloc(bytelen + 1, sizeof(uint8_t));
	memcpy(tmpbuf + 1, buf, bytelen);
	bytes_to_big(bytelen, (const char*) tmpbuf, bigtmp.getbig());
	premult(bigtmp.getbig(), MAXMSGSAMPLE, bigtmp.getbig());
	for (int i = 0; i < MAXMSGSAMPLE; i++) {
		point = EC2(bigtmp, 0);
		if (!point_at_infinity(point.get_point())) {
			*val = point;
			return;
		}
		point = EC2(bigtmp, 1);
		if (!point_at_infinity(point.get_point())) {
			*val = point;
			return;
		}
		incr(bigtmp.getbig(), 1, bigtmp.getbig());
	}
	cerr << "Error while sampling point, exiting!" << endl;
	exit(0);
}

ecc_num::ecc_num(ecc_field* fld) {
	field = fld;
	val = new Big();
}
ecc_num::ecc_num(ecc_field* fld, Big* src) {
	field = fld;
	val = new Big();
	copy(src->getbig(), val->getbig());
}

ecc_num::~ecc_num() {
	//delete val;
}

Big* ecc_num::get_val() {
	return val;
}

void ecc_num::set(num* src) {
	copy(((ecc_num*) src)->get_val()->getbig(), val->getbig());
}
void ecc_num::set_si(int32_t src) {
	convert(src, val->getbig());
}
void ecc_num::set_add(num* a, num* b) {
	add(((ecc_num*) a)->get_val()->getbig(), ((ecc_num*) b)->get_val()->getbig(), val->getbig());
}
void ecc_num::set_mul(num* a, num* b) {
	multiply(((ecc_num*) a)->get_val()->getbig(), ((ecc_num*) b)->get_val()->getbig(), val->getbig());
}

void ecc_num::import_from_bytes(uint8_t* buf, uint32_t field_size_bytes) {
	bytes_to_big(field_size_bytes, (const char*) buf, val->getbig());
}

//export and pad all leading zeros
void ecc_num::export_to_bytes(uint8_t* buf, uint32_t field_size_bytes) {
	big_to_bytes((int32_t) field_size_bytes, val->getbig(), (char*) buf, true);
}

// ecc_brickexp methods
ecc_brickexp::ecc_brickexp(fe* point, ecc_fparams* fparams) {
	Big x, y;
	fe2ec2(point)->getxy(x, y);
	ebrick2_init(&br, x.getbig(), y.getbig(), fparams->BA->getbig(), fparams->BB->getbig(), fparams->m, fparams->a, fparams->b, fparams->c, 8, fparams->secparam);
}

void ecc_brickexp::pow(fe* result, num* e) {
	Big xtmp, ytmp;
	mul2_brick(&br, num2Big(e)->getbig(), xtmp.getbig(), ytmp.getbig());
	*fe2ec2(result) = EC2(xtmp, ytmp);
}

// general methods

void byte_to_point(EC2 *point, uint32_t field_size_bytes, uint8_t* pBufIdx) {
	uint32_t itmp;
	Big bigtmp;
	itmp = (uint32_t) (pBufIdx[0]);

	bytes_to_big(field_size_bytes - 1, (const char*) (pBufIdx + 1), bigtmp.getbig());
	*point = EC2(bigtmp, itmp);
}

void point_to_byte(uint8_t* pBufIdx, uint32_t field_size_bytes, EC2* point) {
	uint32_t itmp;
	Big bigtmp;
	//compress to x-point and y-bit and convert to byte array
	itmp = point->get(bigtmp);

	//first store the y-bit
	pBufIdx[0] = (uint8_t) (itmp & 0x01);

	//then store the x-coordinate (sec-param/8 byte size)
	big_to_bytes(field_size_bytes - 1, bigtmp.getbig(), (char*) pBufIdx + 1, true);

}
