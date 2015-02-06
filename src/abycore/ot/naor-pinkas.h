/**
 \file 		naor-pinkas.h
 \author 	michael.zohner@ec-spride.de
 \copyright __________________
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
