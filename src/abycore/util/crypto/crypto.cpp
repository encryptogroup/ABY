/**
 \file 		crypto.cpp
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
 \brief		Implementation of crypto primitive class
 */

#include "crypto.h"

crypto::crypto(uint32_t symsecbits, uint8_t* seed) {
	init(symsecbits, seed);
}

crypto::crypto(uint32_t symsecbits) {
	uint8_t* seed = (uint8_t*) malloc(sizeof(uint8_t) * AES_BYTES);
	gen_secure_random(seed, AES_BYTES);

	init(symsecbits, seed);
	free(seed);
}

crypto::~crypto() {
	free_prf_state(&global_prf_state);
	free(aes_hash_in_buf);
	free(aes_hash_out_buf);
	free(sha_hash_buf);
	free(aes_hash_buf_y1);
	free(aes_hash_buf_y2);

#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	clean_aes_key(&aes_hash_key);
	clean_aes_key(&aes_enc_key);
	clean_aes_key(&aes_dec_key);
#endif
}

void crypto::init(uint32_t symsecbits, uint8_t* seed) {
	secparam = get_sec_lvl(symsecbits);

#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	aes_hash_key = EVP_CIPHER_CTX_new();
	aes_enc_key = EVP_CIPHER_CTX_new();
	aes_dec_key = EVP_CIPHER_CTX_new();
#endif

	init_prf_state(&global_prf_state, seed);

	aes_hash_in_buf = (uint8_t*) malloc(AES_BYTES);
	aes_hash_out_buf = (uint8_t*) malloc(AES_BYTES);
	aes_hash_buf_y1 = (uint8_t*) malloc(AES_BYTES);
	aes_hash_buf_y2 = (uint8_t*) malloc(AES_BYTES);

	if (secparam.symbits == ST.symbits) {
		hash_routine = &sha1_hash;
		sha_hash_buf = (uint8_t*) malloc(SHA1_OUT_BYTES);
	} else if (secparam.symbits == MT.symbits) {
		hash_routine = &sha256_hash;
		sha_hash_buf = (uint8_t*) malloc(SHA256_OUT_BYTES);
	} else if (secparam.symbits == LT.symbits) {
		hash_routine = &sha256_hash;
		sha_hash_buf = (uint8_t*) malloc(SHA256_OUT_BYTES);
	} else if (secparam.symbits == XLT.symbits) {
		hash_routine = &sha512_hash;
		sha_hash_buf = (uint8_t*) malloc(SHA512_OUT_BYTES);
	} else if (secparam.symbits == XXLT.symbits) {
		hash_routine = &sha512_hash;
		sha_hash_buf = (uint8_t*) malloc(SHA512_OUT_BYTES);
	} else {
		hash_routine = &sha256_hash;
		sha_hash_buf = (uint8_t*) malloc(SHA256_OUT_BYTES);
	}
}

pk_crypto* crypto::gen_field(field_type ftype) {
	uint8_t* pkseed = (uint8_t*) malloc(sizeof(uint8_t) * (secparam.symbits >> 3));
	gen_rnd(pkseed, secparam.symbits >> 3);
	pk_crypto* ret;
	if (ftype == P_FIELD)
		ret = new prime_field(secparam, pkseed);
	else
		ret = new ecc_field(secparam, pkseed);
	free(pkseed);
	return ret;
}

void gen_rnd_bytes(prf_state_ctx* prf_state, uint8_t* resbuf, uint32_t nbytes) {
	AES_KEY_CTX* aes_key;
	uint64_t* rndctr;
	uint8_t* tmpbuf;
	uint32_t i, size;
	int32_t dummy;

	aes_key = &(prf_state->aes_key);
	rndctr = prf_state->ctr;
	size = ceil_divide(nbytes, AES_BYTES);
	tmpbuf = (uint8_t*) malloc(sizeof(uint8_t) * size * AES_BYTES);

	//TODO it might be better to store the result directly in resbuf but this would require the invoking routine to pad it to a multiple of AES_BYTES
	for (i = 0; i < size; i++, rndctr[0]++) {
#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
		EVP_EncryptUpdate(*aes_key, tmpbuf + i * AES_BYTES, &dummy, (uint8_t*) rndctr, AES_BYTES);
#else
		EVP_EncryptUpdate(aes_key, tmpbuf + i * AES_BYTES, &dummy, (uint8_t*) rndctr, AES_BYTES);
#endif
	}
	memcpy(resbuf, tmpbuf, nbytes);

	free(tmpbuf);
}

void crypto::gen_rnd(uint8_t* resbuf, uint32_t nbytes) {
	gen_rnd_bytes(&global_prf_state, resbuf, nbytes);
}

void crypto::gen_rnd_uniform(uint32_t* res, uint32_t mod) {
	//pad to multiple of 4 bytes for uint32_t length
	uint32_t nrndbytes = PadToMultiple(bits_in_bytes(secparam.symbits) + ceil_log2(mod), sizeof(uint32_t));
	uint64_t bitsint = (8*sizeof(uint32_t));
	uint32_t rnditers = ceil_divide(nrndbytes * 8, bitsint);

	uint32_t* rndbuf = (uint32_t*) malloc(nrndbytes);
	gen_rnd((uint8_t*) rndbuf, nrndbytes);

	uint64_t tmpval = 0, tmpmod = mod;

	for(uint32_t i = 0; i < rnditers; i++) {
		tmpval = (((uint64_t) (tmpval << bitsint)) | ((uint64_t)rndbuf[i]));
		tmpval %= tmpmod;
	}
	*res = (uint32_t) tmpval;
	free(rndbuf);
}
void crypto::gen_rnd_from_seed(uint8_t* resbuf, uint32_t resbytes, uint8_t* seed) {
	prf_state_ctx tmpstate;
	init_prf_state(&tmpstate, seed);
	gen_rnd_bytes(&tmpstate, resbuf, resbytes);
	free_prf_state(&tmpstate);
}

void crypto::encrypt(AES_KEY_CTX* enc_key, uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes) {
	int32_t dummy;
#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	EVP_EncryptUpdate(*enc_key, resbuf, &dummy, inbuf, ninbytes);
#else
	EVP_EncryptUpdate(enc_key, resbuf, &dummy, inbuf, ninbytes);
#endif
	//EVP_EncryptFinal_ex(enc_key, resbuf, &dummy);
}
void crypto::decrypt(AES_KEY_CTX* dec_key, uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes) {
	int32_t dummy;
#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	EVP_DecryptUpdate(*dec_key, resbuf, &dummy, inbuf, ninbytes);
#else
	EVP_DecryptUpdate(dec_key, resbuf, &dummy, inbuf, ninbytes);
#endif
	//EVP_DecryptFinal_ex(dec_key, resbuf, &dummy);
}

void crypto::encrypt(uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes) {
	encrypt(&aes_enc_key, resbuf, inbuf, ninbytes);
}

void crypto::decrypt(uint8_t* resbuf, uint8_t* inbuf, uint32_t ninbytes) {
	decrypt(&aes_dec_key, resbuf, inbuf, ninbytes);
}

void crypto::seed_aes_hash(uint8_t* seed, bc_mode mode, const uint8_t* iv) {
	seed_aes_key(&aes_hash_key, seed, mode, iv);
}

void crypto::seed_aes_enc(uint8_t* seed, bc_mode mode, const uint8_t* iv) {
	seed_aes_key(&aes_enc_key, seed, mode, iv, true);
	seed_aes_key(&aes_dec_key, seed, mode, iv, false);
}

void crypto::init_aes_key(AES_KEY_CTX* aes_key, uint8_t* seed, bc_mode mode, const uint8_t* iv) {
	seed_aes_key(aes_key, seed, mode, iv);
}

void crypto::init_aes_key(AES_KEY_CTX* aes_key, uint32_t symbits, uint8_t* seed, bc_mode mode, const uint8_t* iv, bool encrypt) {
	seed_aes_key(aes_key, symbits, seed, mode, iv, encrypt);
}

void crypto::seed_aes_key(AES_KEY_CTX* aeskey, uint8_t* seed, bc_mode mode, const uint8_t* iv, bool encrypt) {
	seed_aes_key(aeskey, secparam.symbits, seed, mode, iv);
}

void crypto::clean_aes_key(AES_KEY_CTX* aeskey) {
#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	EVP_CIPHER_CTX_free(*aeskey);
#else
	EVP_CIPHER_CTX_cleanup(aeskey);
#endif
}

void crypto::seed_aes_key(AES_KEY_CTX* aeskey, uint32_t symbits, uint8_t* seed, bc_mode mode, const uint8_t* iv, bool encrypt) {
#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	*aeskey = EVP_CIPHER_CTX_new();
	AES_KEY_CTX aes_key_tmp = *aeskey;
#else
	EVP_CIPHER_CTX_init(aeskey);
	AES_KEY_CTX* aes_key_tmp = aeskey;
#endif
	int (*initfct)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*);

	if (encrypt)
		initfct = EVP_EncryptInit_ex;
	else
		initfct = EVP_DecryptInit_ex;

	switch (mode) {
	case ECB:
		if (symbits <= 128) {
			initfct(aes_key_tmp, EVP_aes_128_ecb(), NULL, seed, iv);
		} else if(symbits == 192) {
			initfct(aes_key_tmp, EVP_aes_192_ecb(), NULL, seed, iv);
		} else {
			initfct(aes_key_tmp, EVP_aes_256_ecb(), NULL, seed, iv);
		}
		break;
	case CBC:
		if (symbits <= 128) {
			initfct(aes_key_tmp, EVP_aes_128_cbc(), NULL, seed, iv);
		} else if(symbits == 192) {
			initfct(aes_key_tmp, EVP_aes_192_cbc(), NULL, seed, iv);
		} else {
			initfct(aes_key_tmp, EVP_aes_256_cbc(), NULL, seed, iv);
		}
		break;
	default:
		if (symbits <= 128) {
			initfct(aes_key_tmp, EVP_aes_128_ecb(), NULL, seed, iv);
		} else if(symbits == 192) {
			initfct(aes_key_tmp, EVP_aes_192_ecb(), NULL, seed, iv);
		} else {
			initfct(aes_key_tmp, EVP_aes_256_ecb(), NULL, seed, iv);
		}
		break;
	}
}

void crypto::hash_ctr(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes, uint64_t ctr) {
	uint8_t* tmpbuf = (uint8_t*) malloc(ninbytes + sizeof(uint64_t));
	memcpy(tmpbuf, &ctr, sizeof(uint64_t));
	memcpy(tmpbuf + sizeof(uint64_t), inbuf, ninbytes);
	hash_routine(resbuf, noutbytes, tmpbuf, ninbytes+sizeof(uint64_t), sha_hash_buf);
	free(tmpbuf);
}

void crypto::hash(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes) {
	uint8_t* hash_buf = (uint8_t*) malloc(get_hash_bytes());
	hash_routine(resbuf, noutbytes, inbuf, ninbytes, hash_buf);
	free(hash_buf);
}

void crypto::hash_buf(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes, uint8_t* buf) {
	hash_routine(resbuf, noutbytes, inbuf, ninbytes, buf);
}

void crypto::hash_non_threadsafe(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes) {
	hash_routine(resbuf, noutbytes, inbuf, ninbytes, sha_hash_buf);
}

//A fixed-key hashing scheme that uses AES, should not be used for real hashing, hashes to AES_BYTES bytes
void crypto::fixed_key_aes_hash(AES_KEY_CTX* aes_key, uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes) {
	uint32_t i;
	int32_t dummy;

	memset(aes_hash_in_buf, 0, AES_BYTES);
	memcpy(aes_hash_in_buf, inbuf, ninbytes);

	//two encryption iterations TODO: not secure since both blocks are treated independently, implement DM or MMO
#ifdef OPENSSL_OPAQUE_EVP_CIPHER_CTX
	EVP_EncryptUpdate(*aes_key, aes_hash_out_buf, &dummy, aes_hash_in_buf, AES_BYTES);
#else
	EVP_EncryptUpdate(aes_key, aes_hash_out_buf, &dummy, aes_hash_in_buf, AES_BYTES);
#endif

	((uint64_t*) aes_hash_out_buf)[0] ^= ((uint64_t*) aes_hash_in_buf)[0];
	((uint64_t*) aes_hash_out_buf)[1] ^= ((uint64_t*) aes_hash_in_buf)[1];

	memcpy(resbuf, aes_hash_out_buf, noutbytes);
}

//Generate a random permutation of neles elements using Knuths algorithm
void crypto::gen_rnd_perm(uint32_t* perm, uint32_t neles) {
	uint32_t* rndbuf = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint32_t i, j;
	//TODO Generate random numbers (CAREFUL: NOT UNIFORM)
	gen_rnd((uint8_t*) rndbuf, sizeof(uint32_t) * neles);
	for (i = 0; i < neles; i++) {
		perm[i] = i;
	}
	for (i = 0; i < neles; i++) {
		j = rndbuf[i] % neles; //NOT UNIFORM
		swap(perm[i], perm[j]);
	}
	free(rndbuf);
}

uint32_t crypto::get_aes_key_bytes() {
	if (secparam.symbits == ST.symbits)
		return 16;
	else if (secparam.symbits == MT.symbits)
		return 16;
	else if (secparam.symbits == LT.symbits)
		return 16;
	else if (secparam.symbits == XLT.symbits)
		return 24;
	else if (secparam.symbits == XXLT.symbits)
		return 32;
	else
		return 64;
}

uint32_t crypto::get_hash_bytes() {
	if (secparam.symbits == ST.symbits)
		return 20;
	else if (secparam.symbits == MT.symbits)
		return 32;
	else if (secparam.symbits == LT.symbits)
		return 32;
	else if (secparam.symbits == XLT.symbits)
		return 64;
	else if (secparam.symbits == XXLT.symbits)
		return 64;
	else
		return 64;
}

//Generate a common seed, is only secure in the semi-honest model
void crypto::gen_common_seed(prf_state_ctx* prf_state, CSocket& sock) {
	uint8_t *seed_buf, *seed_rcv_buf;
	uint32_t seed_bytes, i;

	seed_bytes = get_aes_key_bytes();
	seed_buf = (uint8_t*) malloc(seed_bytes);
	seed_rcv_buf = (uint8_t*) malloc(seed_bytes);

	//randomly generate and exchange seed bytes:
	gen_rnd(seed_buf, seed_bytes);
	sock.Send(seed_buf, seed_bytes);
	sock.Receive(seed_rcv_buf, seed_bytes);

	//xor both seeds
	for (i = 0; i < seed_bytes; i++) {
		seed_buf[i] ^= seed_rcv_buf[i];
	}

	init_prf_state(prf_state, seed_buf);

	free(seed_buf);
	free(seed_rcv_buf);
}

void crypto::init_prf_state(prf_state_ctx* prf_state, uint8_t* seed) {
	seed_aes_key(&(prf_state->aes_key), seed);
	prf_state->ctr = (uint64_t*) calloc(ceil_divide(secparam.symbits, 8 * sizeof(uint64_t)), sizeof(uint64_t));
}

void crypto::free_prf_state(prf_state_ctx* prf_state) {
	free(prf_state->ctr);
	clean_aes_key(&(prf_state->aes_key));
}

void des_encrypt(uint8_t* resbuf, uint8_t* inbuf, uint8_t* key, bool encrypt) {
	DES_cblock      keyblock;
	DES_cblock		msgblock;
	DES_cblock		outblock;
	DES_key_schedule schedule;

	memcpy(msgblock, inbuf, 8);
	memcpy( keyblock, key,8);
	DES_set_key( &keyblock, &schedule );

	/* Encryption occurs here */
	DES_ecb_encrypt(&msgblock, &outblock, &schedule, (int) encrypt);

	memcpy(resbuf, outblock, 8);
}


void des3_encrypt(uint8_t* resbuf, uint8_t* inbuf, uint8_t* key, bool encrypt) {
	DES_cblock      keyblock1, keyblock2, keyblock3;
	DES_cblock		msgblock;
	DES_cblock		outblock;
	DES_key_schedule schedule1, schedule2, schedule3;

	memcpy(msgblock, inbuf, 8);

	memcpy( keyblock1, key,8);
	memcpy( keyblock2, key+8,8);
	memcpy( keyblock2, key+16,8);

	DES_set_key( &keyblock1, &schedule1 );
	DES_set_key( &keyblock2, &schedule2 );
	DES_set_key( &keyblock3, &schedule3 );

	/* Encryption occurs here */
	DES_ecb3_encrypt(&msgblock, &outblock, &schedule1, &schedule2, &schedule2, (int) encrypt);

	memcpy(resbuf, outblock, 8);
}


void sha1_hash(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes, uint8_t* hash_buf) {
	SHA_CTX sha;
	SHA1_Init(&sha);
	SHA1_Update(&sha, inbuf, ninbytes);
	SHA1_Final(hash_buf, &sha);
	memcpy(resbuf, hash_buf, noutbytes);
}

void sha256_hash(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes, uint8_t* hash_buf) {
	SHA256_CTX sha;
	SHA256_Init(&sha);
	SHA256_Update(&sha, inbuf, ninbytes);
	SHA256_Final(hash_buf, &sha);
	memcpy(resbuf, hash_buf, noutbytes);
}

void sha512_hash(uint8_t* resbuf, uint32_t noutbytes, uint8_t* inbuf, uint32_t ninbytes, uint8_t* hash_buf) {
	SHA512_CTX sha;
	SHA512_Init(&sha);
	SHA512_Update(&sha, inbuf, ninbytes);
	SHA512_Final(hash_buf, &sha);
	memcpy(resbuf, hash_buf, noutbytes);
}

//Read random bytes from /dev/random - copied from stackoverflow (post by zneak)
void gen_secure_random(uint8_t* dest, uint32_t nbytes) {
	int fd = open("/dev/random", O_RDONLY);
	if (fd < 0)
	{
		cerr << "Unable to open /dev/random, exiting" << endl;
		exit(0);
	}
	size_t bytectr = 0;
	while (bytectr < nbytes) {
		ssize_t result = read(fd, dest + bytectr, nbytes - bytectr);
		if (result < 0) {
			cerr << "Unable to read from /dev/random, exiting" << endl;
			exit(0);
		}
		bytectr += static_cast<size_t>(result);
	}
	if (close(fd) < 0)
	{
		cerr << "Unable to close /dev/random" << endl;
	}
}

seclvl get_sec_lvl(uint32_t symsecbits) {
	if (symsecbits == ST.symbits)
		return ST;
	else if (symsecbits == MT.symbits)
		return MT;
	else if (symsecbits == LT.symbits)
		return LT;
	else if (symsecbits == XLT.symbits)
		return XLT;
	else if (symsecbits == XXLT.symbits)
		return XXLT;
	else
		return LT;
}
