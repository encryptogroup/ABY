/**
 \file 		maskingfunction.h
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
 \brief		Masking Function implementation.
 */

#ifndef MASKINGFUNCTION_H_
#define MASKINGFUNCTION_H_

#include "../util/cbitvector.h"
#include "../util/typedefs.h"

class MaskingFunction {

public:
	MaskingFunction() {
	}
	;
	~MaskingFunction() {
	}
	;

	virtual void Mask(uint32_t progress, uint32_t len, CBitVector* values, CBitVector* snd_buf, BYTE protocol) = 0;
	virtual void UnMask(uint32_t progress, uint32_t len, CBitVector& choices, CBitVector& output, CBitVector& rcv_buf, CBitVector& tmpmask, BYTE version) = 0;
	virtual void expandMask(CBitVector& out, BYTE* sbp, uint32_t offset, uint32_t processedOTs, uint32_t bitlength, crypto* crypt) = 0;

protected:

};

#endif /* MASKINGFUNCTION_H_ */
