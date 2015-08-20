/**
 \file 		baseOT.h
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
	virtual ~BaseOT() {
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
