/**
 \file 		naor-pinkas.h
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
 \brief		Compute the Naor-Pinkas Base OTs
 */

#ifndef __Naor_Pinkas_H_
#define __Naor_Pinkas_H_

#include "baseOT.h"

class NaorPinkas: public BaseOT {

public:

	NaorPinkas(crypto* crypt, field_type ftype) :
			BaseOT(crypt, ftype) {
	}
	;
	//TODO call super class to delete the pkcrypto object
	~NaorPinkas() {
	}
	;

	void Receiver(uint32_t nSndVals, uint32_t nOTs, CBitVector& choices, CSocket& sock, BYTE* ret);
	void Sender(uint32_t nSndVals, uint32_t nOTs, CSocket& sock, BYTE* ret);

};

#endif
