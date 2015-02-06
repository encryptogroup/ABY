/**
 \file 		xormasking.h
 \author 	michael.zohner@ec-spride.de
 \copyright __________________
 \brief		XOR Masking
 */

#ifndef XORMASKING_H_
#define XORMASKING_H_

#include "maskingfunction.h"

class XORMasking: public MaskingFunction {
public:
	XORMasking(uint32_t bitlength) {
		init(bitlength);
	}
	;
	XORMasking(uint32_t bitlength, CBitVector& delta) {
		m_vDelta = &delta;
		init(bitlength);
	}
	;
	~XORMasking() {
	}
	;

	void init(uint32_t bitlength) {
		m_nBitLength = bitlength;
	}

	void Mask(uint32_t progress, uint32_t processedOTs, CBitVector* values, CBitVector* snd_buf, BYTE protocol) {
		uint32_t nsndvals = 2;

		if (protocol == G_OT) {
			snd_buf[0].XORBytes(values[0].GetArr() + ceil_divide(progress * m_nBitLength, 8), 0, ceil_divide(processedOTs * m_nBitLength, 8));
			snd_buf[1].XORBytes(values[1].GetArr() + ceil_divide(progress * m_nBitLength, 8), 0, ceil_divide(processedOTs * m_nBitLength, 8));
		} else if (protocol == C_OT) {
			values[0].SetBytes(snd_buf[0].GetArr(), ceil_divide(progress * m_nBitLength, 8), ceil_divide(processedOTs * m_nBitLength, 8)); //.SetBits(hash_buf, i*m_nBitLength, m_nBitLength);
			int bitPos = progress * m_nBitLength;
			int length = processedOTs * m_nBitLength;
			int bytePos = ceil_divide(bitPos, 8);

			values[1].SetBits(values[0].GetArr() + bytePos, bitPos, length);
			values[1].XORBits(m_vDelta->GetArr() + bytePos, bitPos, length);
			snd_buf[1].XORBits(values[1].GetArr() + bytePos, 0, length);
		}
		else if (protocol == R_OT) {
			values[0].SetBytes(snd_buf[0].GetArr(), ceil_divide(progress * m_nBitLength, 8), ceil_divide(processedOTs * m_nBitLength, 8));
			values[1].SetBytes(snd_buf[1].GetArr(), ceil_divide(progress * m_nBitLength, 8), ceil_divide(processedOTs * m_nBitLength, 8));
		}
	}
	;

	//output already has to contain the masks
	void UnMask(uint32_t progress, uint32_t processedOTs, CBitVector& choices, CBitVector& output, CBitVector& rcv_buf, CBitVector& tmpmask, BYTE protocol) {
		uint32_t bytelen = ceil_divide(m_nBitLength, 8);
		uint32_t gprogress = progress * bytelen;
		uint32_t lim = progress + processedOTs;

		if (protocol == G_OT) {
			for (uint32_t u, i = progress, offset = processedOTs * bytelen, l = 0; i < lim; i++, gprogress += bytelen, l += bytelen) {
				//TODO make this working for single bits
				u = (uint32_t) choices.GetBitNoMask(i);
				output.SetXOR(rcv_buf.GetArr() + (u * offset) + l, tmpmask.GetArr() + gprogress, gprogress, bytelen);
			}

		} else if (protocol == C_OT)
				{
			int gprogress = progress * bytelen;
			output.Copy(tmpmask.GetArr() + gprogress, gprogress, bytelen * processedOTs);
			for (int i = progress, l = 0; i < lim; i++, l += bytelen, gprogress += bytelen) {
				if (choices.GetBitNoMask(i)) {
					//TODO make this working for single bits
					output.XORBytes(rcv_buf.GetArr() + l, gprogress, bytelen);
				}
			}
		} else if (protocol == R_OT) {
			//The seed expansion has already been performed, so do nothing
		}
	}
	;

	void expandMask(CBitVector& out, BYTE* sbp, uint32_t offset, uint32_t processedOTs, uint32_t bitlength, crypto* crypt) {

		if (bitlength <= AES_KEY_BITS) {
			for (uint32_t i = 0; i < processedOTs; i++, sbp += AES_KEY_BYTES) {
				out.SetBits(sbp, (uint64_t) (offset + i) * bitlength, (uint64_t) bitlength);
			}
		} else {
			BYTE m_bBuf[AES_BYTES];
			BYTE ctr_buf[AES_BYTES] = { 0 };
			uint32_t counter = *((uint32_t*) ctr_buf);
			AES_KEY_CTX tkey;
			for (uint32_t i = 0, rem; i < processedOTs; i++, sbp += AES_KEY_BYTES) {
				crypt->init_aes_key(&tkey, sbp);
				for (counter = 0; counter < bitlength / AES_BITS; counter++) {
					crypt->encrypt(&tkey, m_bBuf, ctr_buf, AES_BYTES);
					out.SetBits(m_bBuf, ((uint64_t) offset + i) * bitlength + (counter * AES_BITS), (uint64_t) AES_BITS);
				}
				//the final bits
				if ((rem = bitlength - (counter * AES_BITS)) > 0) {
					crypt->encrypt(&tkey, m_bBuf, ctr_buf, AES_BYTES);
					out.SetBits(m_bBuf, ((uint64_t) offset + i) * bitlength + (counter * AES_BITS), (uint64_t) rem);
				}
			}
		}
	}

private:
	CBitVector* m_vDelta;
	uint32_t m_nBitLength;
};

#endif /* XORMASKING_H_ */
