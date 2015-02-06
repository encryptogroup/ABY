/**
 \file 		maskingfunction.h
 \author 	michael.zohner@ec-spride.de
 \copyright __________________
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
