/**
 \file 		baseOT.h
 \author 	michael.zohner@ec-spride.de
 \copyright __________________
 \brief		baseOT implementation
 */

#ifndef BASEOT_H_
#define BASEOT_H_

#include "../util/typedefs.h"
#include "../util/cbitvector.h"
#include "../util/socket.h"
#include "../util/crypto/crypto.h"
#include <ctime>

#include <iostream>
#include <cstring>
#include <fstream>
#include <time.h>

class BaseOT {
public:
	BaseOT(crypto* crypt, field_type ftype) {
		m_cCrypto = crypt;
		m_cPKCrypto = crypt->gen_field(ftype);
	}
	;
	~BaseOT() {
		delete m_cPKCrypto;
	}
	;

	virtual void Sender(uint32_t nSndVals, uint32_t nOTs, CSocket& sock, uint8_t* ret) = 0;
	virtual void Receiver(uint32_t nSndVals, uint32_t uint32_t, CBitVector& choices, CSocket& sock, uint8_t* ret) = 0;

protected:

	crypto* m_cCrypto;
	pk_crypto* m_cPKCrypto;

	void hashReturn(uint8_t* ret, uint32_t ret_len, uint8_t* val, uint32_t val_len, uint32_t ctr) {
		m_cCrypto->hash_ctr(ret, ret_len, val, val_len, ctr);
	}

};

#endif /* BASEOT_H_ */
