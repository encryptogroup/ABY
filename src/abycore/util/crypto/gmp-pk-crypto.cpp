/**
 \file 		gmp-pk-crypto.cpp
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
 \brief		Implementation of finite-field-cryptography operations (using the GMP library)
 */

#include "gmp-pk-crypto.h"

//Parameters for different security levels
const char* ifcp1024 =
		"B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
const char* ifcg1024 =
		"A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";
const char* ifcq1024 = "F518AA8781A8DF278ABA4E7D64B7CB9D49462353";

const char* ifcp2048 =
		"AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F";
const char* ifcg2048 =
		"AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA";
const char* ifcq2048 = "801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB";

const char* ifcp3072 =
		"4660194093823565506151007332698542081380390944320667936220310340292682538415201463451360005469701273992420569531194415296871671272562243754789577412471203509686259933515539120145538889500684305065682267020422897056483203401642088590732633756278140548667640739272073464322452643609409839498807131787408915921523565001045685221279165409792825261753615641493423723165471868882028678262386826730035778207616806238910696112513243832793252430036079010833108716296401084350809152423357477416465451376967706115065572717893335336664895800189754170750266169252030669114411476002012410621336179123441424048589750501111541393610787337793314723136089502117079738181113934544472215273637670210480814609550715859453809706797176331069587697357167970759889883398852942449568449890603652456531060380065260476714266615239827983706919432589669744367350756821903843388105282430635020233707272521317674908786962912228887786913664926989228941514639";
const char* ifcg3072 =
		"326984479748743614358878489890111032378521682641889472728164592588245254735528952815040417677135099463681521117067228131302984716932197927691804537047698386112034189358693637764887258325546424576668654933254773228919028116187485325776123548207630122958160311311825230114818910264101591293903307807790394765896174615027850669640300925521032111542648598127663424462192520490917608209583615366128345913820058976254028107968965281721876376153097516948596625654797921929621363755081263164203185942482227411046415127689226121648774535224687708280963930985498313715804706762069594298539593719253724193098201932449349224692341850008449711165375995101343314201170357859203662648251088921851885444086613889195257606710405156897225917687758015354941738963422772322756212536951044725465040734436163477969317027796051497934165333064621979305683254912099909723895352817468375097484456065145582788954244042708099846989842764657922387568064";
const char* ifcq3072 = "95729504467608377623766753562217147614989054519467474668915026082895293552781";

gmp_num::gmp_num(prime_field* fld) {
	field = fld;
	mpz_init(val);
}
gmp_num::gmp_num(prime_field* fld, mpz_t src) {
	field = fld;
	mpz_init(val);
	mpz_set(val, src);
}

gmp_num::~gmp_num() {
	mpz_clear(val);
}

mpz_t* gmp_num::get_val() {
	return &val;
}

void gmp_num::set(num* src) {
	mpz_set(val, *num2mpz(src));
}
void gmp_num::set_si(int32_t src) {
	mpz_set_si(val, src);
}
void gmp_num::set_add(num* a, num* b) {
	mpz_add(val, *num2mpz(a), *num2mpz(b));
}
//a-b
void gmp_num::set_sub(num* a, num* b) {
	mpz_sub(val, *num2mpz(a), *num2mpz(b));
}
void gmp_num::set_mul(num* a, num* b) {
	mpz_mul(val, *num2mpz(a), *num2mpz(b));
}
void gmp_num::mod(num* modulus) {
	mpz_mod(val, val, *num2mpz(modulus));
}
void gmp_num::set_mul_mod(num* a, num* b, num* modulus) {
	set_mul(a, b);
	mod(modulus);
}

void gmp_num::import_from_bytes(uint8_t* buf, uint32_t field_size_bytes) {
	mpz_import(val, field_size_bytes, 1, sizeof((buf)[0]), 0, 0, (buf));
}

//export and pad all leading zeros
void gmp_num::export_to_bytes(uint8_t* buf, uint32_t field_size_bytes) {
	mpz_export_padded(buf, field_size_bytes, val);
}

num* prime_field::get_rnd_num(uint32_t bitlen) {
	mpz_t val;
	if (bitlen == 0)
		bitlen = secparam.ifcbits;
	mpz_init(val);
	mpz_urandomm(val, rnd_state, q);
	num* ret = new gmp_num(this, val);
	mpz_clear(val);
	return ret;
}

fe* prime_field::get_rnd_fe(uint32_t bitlen) {
	mpz_t val;
	mpz_init(val);
	mpz_urandomm(val, rnd_state, q);
	fe* ret = new gmp_fe(this, val);
	mpz_clear(val);
	return ret;
}

gmp_fe::gmp_fe(prime_field* fld) {
	field = fld;
	init();
}

gmp_fe::gmp_fe(prime_field* fld, mpz_t src) {
	field = fld;
	init();
	mpz_set(val, src);
}
gmp_fe::~gmp_fe() {
	mpz_clear(val);
}

void gmp_fe::set(fe* src) {
	mpz_set(val, *fe2mpz(src));
}
mpz_t* gmp_fe::get_val() {
	return &val;
}

void gmp_fe::set_mul(fe* a, fe* b) {
	mpz_mul(val, *fe2mpz(a), *fe2mpz(b));
	mpz_mod(val, val, *field->get_p());
}

void gmp_fe::set_pow(fe* b, num* e) {
	mpz_powm(val, *fe2mpz(b), *num2mpz(e), *field->get_p());
}

void gmp_fe::set_div(fe* a, fe* b) {
	mpz_invert(val, *fe2mpz(b), *field->get_p());
	mpz_mul(val, *fe2mpz(a), val);
	mpz_mod(val, val, *field->get_p());
}

void gmp_fe::set_double_pow_mul(fe* b1, num* e1, fe* b2, num* e2) {
	gmp_fe tmpa(field), tmpb(field);
	tmpa.set_pow(b1, e1);
	tmpb.set_pow(b2, e2);
	set_mul(&tmpa, &tmpb);
}

void gmp_fe::import_from_bytes(uint8_t* buf) {
	mpz_import(val, field->fe_byte_size(), 1, sizeof((buf)[0]), 0, 0, (buf));
}
//export and pad all leading zeros
void gmp_fe::export_to_bytes(uint8_t* buf) {
	mpz_export_padded(buf, field->fe_byte_size(), val);
}

void gmp_fe::sample_fe_from_bytes(uint8_t* buf, uint32_t bytelen) {
	mpz_import(val, bytelen, 1, sizeof((buf)[0]), 0, 0, (buf));
	mpz_mod(val, val, *field->get_p());
}
bool gmp_fe::eq(fe* a) {
	return mpz_cmp(val, *fe2mpz(a)) == 0;
}

num* prime_field::get_num() {
	return new gmp_num(this);
}
fe* prime_field::get_fe() {
	return new gmp_fe(this);
}
mpz_t* prime_field::get_p() {
	return &p;
}
fe* prime_field::get_generator() {
	return new gmp_fe(this, g);
}
num* prime_field::get_order() {
	num* val = get_num();
	val->set(order);
	return val;
}

fe* prime_field::get_rnd_generator() {
	mpz_t tmp;
	mpz_init(tmp);
	//sample random hi -- sample random element x in Zp, and then compute x^{(p-1)/q} mod p
	do {
		mpz_urandomb(tmp, rnd_state, secparam.ifcbits);
		mpz_mod(tmp, tmp, p);
		mpz_powm(tmp, tmp, q, p);
	} while (!(mpz_cmp_ui(tmp, (uint32_t ) 1)));
	fe* ret = new gmp_fe(this, tmp);
	mpz_clear(tmp);
	return ret;
}

brickexp* prime_field::get_brick(fe* gen) {
	return new gmp_brickexp(gen, this);
}

uint32_t prime_field::get_size() {
	return secparam.ifcbits;
}

void prime_field::init(seclvl sp, uint8_t* seed) {
	mpz_t rnd_seed;

	mpz_inits(p, q, g, rnd_seed, NULL);
	secparam = sp;

	mpz_import(rnd_seed, ceil_divide(secparam.symbits, 8), 1, sizeof((seed)[0]), 0, 0, seed);

	if (secparam.ifcbits == ST.ifcbits) {
		mpz_set_str(p, ifcp1024, 16);
		mpz_set_str(g, ifcg1024, 16);
		mpz_set_str(q, ifcq1024, 16);
	} else if (secparam.ifcbits == MT.ifcbits) {
		mpz_set_str(p, ifcp2048, 16);
		mpz_set_str(g, ifcg2048, 16);
		mpz_set_str(q, ifcq2048, 16);
	} else if (secparam.ifcbits == LT.ifcbits) {
		mpz_set_str(p, ifcp3072, 10);
		mpz_set_str(g, ifcg3072, 10);
		mpz_set_str(q, ifcq3072, 10);
	} else //Long term security
	{
		mpz_set_str(p, ifcp3072, 10);
		mpz_set_str(g, ifcg3072, 10);
		mpz_set_str(q, ifcq3072, 10);
	}
	order = new gmp_num(this, q);

	gmp_randinit_default(rnd_state);
	gmp_randseed(rnd_state, rnd_seed);
	fe_bytelen = ceil_divide(secparam.ifcbits, 8);

	mpz_clear(rnd_seed);
}

prime_field::~prime_field() {
	gmp_randclear(rnd_state);
	mpz_clear(p);
	mpz_clear(g);
	mpz_clear(q);
	delete order;
}

gmp_brickexp::~gmp_brickexp() {
	for (uint32_t i = 0; i < m_numberOfElements; i++)
		mpz_clear(m_table[i]);
	free(m_table);
}
;

void gmp_brickexp::init(fe* g, prime_field* pfield) {
	field = pfield;

	m_numberOfElements = field->get_field_size();

	m_table = (mpz_t*) malloc(sizeof(mpz_t) * m_numberOfElements);
	for (uint32_t i = 0; i < m_numberOfElements; i++) {
		mpz_init(m_table[i]);
	}

	mpz_set(m_table[0], *((gmp_fe*) g)->get_val());
	for (unsigned u = 1; u < m_numberOfElements; ++u) {
		mpz_mul(m_table[u], m_table[u - 1], m_table[u - 1]);
		mpz_mod(m_table[u], m_table[u], *field->get_p());
	}
}

void gmp_brickexp::pow(fe* result, num* e) {
	mpz_t* res = ((gmp_fe*) result)->get_val();
	mpz_t* exp = ((gmp_num*) e)->get_val();
	uint32_t u;

	mpz_set_ui(*res, 1);
	for (u = 0; u < m_numberOfElements; u++) {
		if (mpz_tstbit(*exp, u)) {
			mpz_mul(*res, *res, m_table[u]);
			mpz_mod(*res, *res, *field->get_p());
		}
	}
}

// mpz_export does not fill leading zeros, thus a prepending of leading 0s is required
void mpz_export_padded(uint8_t* pBufIdx, uint32_t field_size_bytes, mpz_t to_export) {
	size_t size = 0;
	mpz_export(pBufIdx, &size, 1, sizeof(pBufIdx[0]), 0, 0, to_export);

	if (size < field_size_bytes) {
		for (int i = 0; i + size < field_size_bytes; i++) {
			pBufIdx[i] = 0;
		}
		pBufIdx += (field_size_bytes - size);
		mpz_export(pBufIdx, &size, 1, sizeof(pBufIdx[0]), 0, 0, to_export);
	}
}
