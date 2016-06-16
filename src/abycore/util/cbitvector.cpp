/**
 \file 		cbitvector.cpp
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
 \brief		CBitVector Implementation
 */

#include "cbitvector.h"

/* Fill random values using the pre-defined AES key */
void CBitVector::FillRand(uint32_t bits, crypto* crypt) {
	if (bits > m_nByteSize << 3)
		Create(bits);
	crypt->gen_rnd(m_pBits, ceil_divide(bits, 8));
}

void CBitVector::Create(uint64_t numelements, uint64_t elementlength, crypto* crypt) {
	Create(numelements * elementlength, crypt);
	m_nElementLength = elementlength;
	m_nNumElements = numelements;
	m_nNumElementsDimB = 1;
}

void CBitVector::Create(uint64_t bits, crypto* crypt) {
	Create(bits);
	FillRand(bits, crypt);
}

void CBitVector::Create(uint64_t bits) {
	if (bits == 0)
		bits = AES_BITS;

	if (m_nByteSize > 0) {
		free(m_pBits);
	}

	//TODO: check if padding to aes bits is still necessary, otherwise pad to bytes
	uint64_t size = ceil_divide(bits, AES_BITS);
	m_nByteSize = size * AES_BYTES;
	m_pBits = (BYTE*) calloc(m_nByteSize, sizeof(BYTE));
	assert(m_pBits != NULL);

	m_nElementLength = 1;
	m_nNumElements = m_nByteSize;
	m_nNumElementsDimB = 1;
}

void CBitVector::Create(uint64_t numelements, uint64_t elementlength) {
	Create(((uint64_t) numelements) * elementlength);
	m_nElementLength = elementlength;
	m_nNumElements = numelements;
	m_nNumElementsDimB = 1;
}

void CBitVector::Create(uint64_t numelementsDimA, uint64_t numelementsDimB, uint64_t elementlength) {
	Create(numelementsDimA * numelementsDimB * elementlength);
	m_nElementLength = elementlength;
	m_nNumElements = numelementsDimA;
	m_nNumElementsDimB = numelementsDimB;
}
void CBitVector::Create(uint64_t numelementsDimA, uint64_t numelementsDimB, uint64_t elementlength, crypto* crypt) {
	Create(numelementsDimA * numelementsDimB * elementlength, crypt);
	m_nElementLength = elementlength;
	m_nNumElements = numelementsDimA;
	m_nNumElementsDimB = numelementsDimB;
}

void CBitVector::ResizeinBytes(int newSizeBytes) {
	BYTE* tBits = m_pBits;
	uint64_t tSize = (m_nByteSize<newSizeBytes)? m_nByteSize:newSizeBytes; //fix for overflow condition in memcpy.

	m_nByteSize = newSizeBytes;
	m_pBits = (uint8_t*) calloc(m_nByteSize, sizeof(uint8_t));

	memcpy(m_pBits, tBits, tSize);

	free(tBits);
}

void CBitVector::Copy(BYTE* p, int pos, int len) {
	if (pos + len > m_nByteSize) {
		if (m_pBits)
			ResizeinBytes(pos + len);
		else {
			CreateBytes(pos + len);
		}
	}
	memcpy(m_pBits + pos, p, len);
}

//pos and len in bits
void CBitVector::SetBits(BYTE* p, uint64_t pos, uint64_t len) {
	if (len < 1 || (pos + len) > (m_nByteSize << 3))
		return;

	if (len == 1) {
		SetBitNoMask(pos, *p);
		return;
	}
	if (!((pos & 0x07) || (len & 0x07))) {

		SetBytes(p, pos >> 3, len >> 3);
		return;
	}
	uint64_t posctr = pos >> 3;
	int lowermask = pos & 7;
	int uppermask = 8 - lowermask;

	int i;
	BYTE temp;
	for (i = 0; i < len / (sizeof(BYTE) * 8); i++, posctr++) {
		temp = p[i];
		m_pBits[posctr] = (m_pBits[posctr] & RESET_BIT_POSITIONS[lowermask]) | ((temp << lowermask) & 0xFF);
		m_pBits[posctr + 1] = (m_pBits[posctr + 1] & RESET_BIT_POSITIONS_INV[uppermask]) | (temp >> uppermask);
	}
	int remlen = len & 0x07;
	if (remlen) {
		temp = p[i] & RESET_BIT_POSITIONS[remlen];
		if (remlen <= uppermask) {
			m_pBits[posctr] = (m_pBits[posctr] & (~(((1 << remlen) - 1) << lowermask))) | ((temp << lowermask) & 0xFF);
		} else {
			m_pBits[posctr] = (m_pBits[posctr] & RESET_BIT_POSITIONS[lowermask]) | ((temp << lowermask) & 0xFF);
			m_pBits[posctr + 1] = (m_pBits[posctr + 1] & (~(((1 << (remlen - uppermask)) - 1)))) | (temp >> uppermask);
		}
	}
}


//Set bits given an offset on the bits for p which is not necessarily divisible by 8
void CBitVector::SetBitsPosOffset(BYTE* p, uint64_t ppos, uint64_t pos, uint64_t len) {
	for (uint64_t i = pos, j = ppos; j < ppos + len; i++, j++) {
		m_pBits[i / 8] ^= (((p[j / 8] & (1 << (j % 8))) >> j % 8) << i % 8);
	}
}


void CBitVector::SetBitsToZero(int bitpos, int bitlen) {
	int firstlim = ceil_divide(bitpos, 8);
	int firstlen = ceil_divide(bitlen - (bitpos % 8), 8);
	for (int i = bitpos; i < firstlim; i++) {
		SetBitNoMask(i, 0);
	}
	if (bitlen > 7) {
		memset(m_pBits + firstlim, 0, firstlen);
	}
	for (int i = (firstlim + firstlen) << 8; i < bitpos + bitlen; i++) {
		SetBitNoMask(i, 0);
	}
}

void CBitVector::SetBytesToZero(int bytepos, int bytelen) {
	assert(bytepos + bytelen < m_nByteSize);
	memset(m_pBits + bytepos, 0x00, bytelen);
}

void CBitVector::Invert() {
	for(uint64_t i = 0; i < m_nByteSize; i++) {
		m_pBits[i] = ~m_pBits[i];
	}
}


void CBitVector::GetBits(BYTE* p, int pos, int len) {
	if (len < 1 || (pos + len) > m_nByteSize << 3)
		return;
	if (len == 1) {
		*p = GetBitNoMask(pos);
		return;
	}
	if (!((pos & 0x07) || (len & 0x07))) {
		GetBytes(p, pos >> 3, len >> 3);
		return;
	}
	int posctr = pos >> 3;
	int lowermask = pos & 7;
	int uppermask = 8 - lowermask;

	int i;
	BYTE temp;
	for (i = 0; i < len / (sizeof(BYTE) * 8); i++, posctr++) {
		p[i] = ((m_pBits[posctr] & GET_BIT_POSITIONS[lowermask]) >> lowermask) & 0xFF;
		p[i] |= (m_pBits[posctr + 1] & GET_BIT_POSITIONS_INV[uppermask]) << uppermask;
	}
	int remlen = len & 0x07;
	if (remlen) {
		if (remlen <= uppermask) {
			p[i] = ((m_pBits[posctr] & (((1 << remlen) - 1 << lowermask))) >> lowermask) & 0xFF;
		} else {
			p[i] = ((m_pBits[posctr] & GET_BIT_POSITIONS[lowermask]) >> lowermask) & 0xFF;
			p[i] |= (m_pBits[posctr + 1] & (((1 << (remlen - uppermask)) - 1))) << uppermask;
		}
	}
}

void CBitVector::XORBytesReverse(BYTE* p, int pos, int len) {
	BYTE* src = p;
	BYTE* dst = m_pBits + pos;
	BYTE* lim = dst + len;
	while (dst != lim) {
		*dst++ ^= REVERSE_BYTE_ORDER[*src++];
	}
}

//XOR bits given an offset on the bits for p which is not necessarily divisible by 8
void CBitVector::XORBitsPosOffset(BYTE* p, int ppos, int pos, int len) {
	for (int i = pos, j = ppos; j < ppos + len; i++, j++) {
		m_pBits[i / 8] ^= (((p[j / 8] & (1 << (j % 8))) >> j % 8) << i % 8);
	}
}

void CBitVector::XORBits(BYTE* p, int pos, int len) {
	if (len < 1 || (pos + len) > m_nByteSize << 3) {
		return;
	}
	if (len == 1) {
		XORBitNoMask(pos, *p);
		return;
	}
	if (!((pos & 0x07) || (len & 0x07))) {
		XORBytes(p, pos >> 3, len >> 3);
		return;
	}
	int posctr = pos >> 3;
	int lowermask = pos & 7;
	int uppermask = 8 - lowermask;

	int i;
	BYTE temp;
	for (i = 0; i < len / (sizeof(BYTE) * 8); i++, posctr++) {
		temp = p[i];
		m_pBits[posctr] ^= ((temp << lowermask) & 0xFF);
		m_pBits[posctr + 1] ^= (temp >> uppermask);
	}
	int remlen = len & 0x07;
	if (remlen) {
		temp = p[i] & RESET_BIT_POSITIONS[remlen];
		if (remlen <= uppermask) {
			m_pBits[posctr] ^= ((temp << lowermask) & 0xFF);
		} else {
			m_pBits[posctr] ^= ((temp << lowermask) & 0xFF);
			m_pBits[posctr + 1] ^= (temp >> uppermask);
		}
	}
}

void CBitVector::ORByte(int pos, BYTE p) {
	m_pBits[pos] |= p;
}

//optimized bytewise for set operation
void CBitVector::GetBytes(BYTE* p, int pos, int len) {

	BYTE* src = m_pBits + pos;
	BYTE* dst = p;
	//Do many operations on REGSIZE types first and then (if necessary) use bytewise operations
	GetBytes((REGSIZE*) dst, (REGSIZE*) src, ((REGSIZE*) dst) + (len >> SHIFTVAL));
	dst += ((len >> SHIFTVAL) << SHIFTVAL);
	src += ((len >> SHIFTVAL) << SHIFTVAL);
	GetBytes(dst, src, dst + (len & ((1 << SHIFTVAL) - 1)));
}

template<class T> void CBitVector::GetBytes(T* dst, T* src, T* lim) {
	//TODO:Warning there could be potential memory leak if the src size is less than limit.
	while (dst != lim) {
		*dst++ = *src++;
	}
}

//optimized bytewise XOR operation
void CBitVector::XORBytes(BYTE* p, int pos, int len) {
	if(pos + len > m_nByteSize)
	cout << "pos = " << pos << ", len = " << len << ", bytesize = " << m_nByteSize << endl;
	assert(pos + len <= m_nByteSize);

	BYTE* dst = m_pBits + pos;
	BYTE* src = p;
	//Do many operations on REGSIZE types first and then (if necessary) use bytewise operations
	XORBytes((REGSIZE*) dst, (REGSIZE*) src, ((REGSIZE*) dst) + (len >> SHIFTVAL));
	dst += ((len >> SHIFTVAL) << SHIFTVAL);
	src += ((len >> SHIFTVAL) << SHIFTVAL);
	XORBytes(dst, src, dst + (len & ((1 << SHIFTVAL) - 1)));
}

//Method for directly XORing CBitVectors
void CBitVector::XOR(CBitVector* b) {
	assert(b->GetSize() == m_nByteSize);
	XORBytes(b->GetArr(), 0, m_nByteSize);
}

//Generic bytewise XOR operation
template<class T> void CBitVector::XORBytes(T* dst, T* src, T* lim) {
	while (dst != lim) {
		*dst++ ^= *src++;
	}
}



void CBitVector::XORRepeat(BYTE* p, int pos, int len, int num) {
	unsigned short* dst = (unsigned short*) (m_pBits + pos);
	unsigned short* src = (unsigned short*) p;
	unsigned short* lim = (unsigned short*) (m_pBits + pos + len);
	for (int i = num; dst != lim;) {
		*dst++ ^= *src++;
		if (!(--i)) {
			src = (unsigned short*) p;
			i = num;
		}
	}
}

//optimized bytewise for set operation
void CBitVector::SetBytes(BYTE* p, int pos, int len) {

	BYTE* dst = m_pBits + pos;
	BYTE* src = p;

	//Do many operations on REGSIZE types first and then (if necessary) use bytewise operations
	SetBytes((REGSIZE*) dst, (REGSIZE*) src, ((REGSIZE*) dst) + (len >> SHIFTVAL));
	dst += ((len >> SHIFTVAL) << SHIFTVAL);
	src += ((len >> SHIFTVAL) << SHIFTVAL);
	SetBytes(dst, src, dst + (len & ((1 << SHIFTVAL) - 1)));
}

template<class T> void CBitVector::SetBytes(T* dst, T* src, T* lim) {
	while (dst != lim) {
		*dst++ = *src++;
	}
}

//optimized bytewise for AND operation
void CBitVector::ANDBytes(BYTE* p, int pos, int len) {

	BYTE* dst = m_pBits + pos;
	BYTE* src = p;
	//Do many operations on REGSIZE types first and then (if necessary) use bytewise operations
	ANDBytes((REGSIZE*) dst, (REGSIZE*) src, ((REGSIZE*) dst) + (len >> SHIFTVAL));
	dst += ((len >> SHIFTVAL) << SHIFTVAL);
	src += ((len >> SHIFTVAL) << SHIFTVAL);
	ANDBytes(dst, src, dst + (len & ((1 << SHIFTVAL) - 1)));
}
template<class T> void CBitVector::ANDBytes(T* dst, T* src, T* lim) {
	while (dst != lim) {
		*dst++ &= *src++;
	}
}

void CBitVector::SetXOR(BYTE* p, BYTE* q, int pos, int len) {
	Copy(p, pos, len);
	XORBytes(q, pos, len);
}

void CBitVector::SetAND(BYTE* p, BYTE* q, int pos, int len) {
	Copy(p, pos, len);
	ANDBytes(q, pos, len);
}

//Method for directly ANDing CBitVectors
void CBitVector::AND(CBitVector* b) {
	assert(b->GetSize() == m_nByteSize);
	ANDBytes(b->GetArr(), 0, m_nByteSize);
}

//Cyclic left shift by pos bits
void CBitVector::CLShift(uint64_t pos) {
	uint8_t* tmpbuf = (uint8_t*) malloc(m_nByteSize);
	for(uint64_t i = 0; i < m_nByteSize; i++) {
		tmpbuf[i+pos] = m_pBits[i];
	}
	free(m_pBits);
	m_pBits = tmpbuf;
}


void CBitVector::Print(int fromBit, int toBit) {
	int to = toBit > (m_nByteSize << 3) ? (m_nByteSize << 3) : toBit;
	for (int i = fromBit; i < to; i++) {
		cout << (unsigned int) GetBitNoMask(i);
	}
	cout << endl;
}

void CBitVector::PrintHex(int fromByte, int toByte, bool linebreak) {
	int to = toByte > (m_nByteSize) ? (m_nByteSize) : toByte;
	for (int i = fromByte; i < to; i++) {
		cout << setw(2) << setfill('0') << (hex) << ((unsigned int) m_pBits[i]);
	}
	if(linebreak){
		cout << (dec) << endl;
	}
}

void CBitVector::PrintHex(bool linebreak) {
	for (int i = 0; i < m_nByteSize; i++) {
		cout << setw(2) << setfill('0') << (hex) << ((unsigned int) m_pBits[i]);
	}
	if(linebreak){
		cout << (dec) << endl;
	}
}

void CBitVector::PrintBinaryMasked(int from, int to) {
	int new_to = to > (m_nByteSize<<3) ? (m_nByteSize<<3) : to;

	for (int i = from; i < new_to; i++) {
		cout << (unsigned int) GetBit(i);
	}
	cout << endl;
}

void CBitVector::PrintContent() {
	if (m_nElementLength == 1) {
		PrintHex();
		return;
	}
	if (m_nNumElementsDimB == 1) {
		for (int i = 0; i < m_nNumElements; i++) {
			cout << Get<int>(i) << ", ";
		}
		cout << endl;
	} else {
		for (int i = 0; i < m_nNumElements; i++) {
			cout << "(";
			for (int j = 0; j < m_nNumElementsDimB - 1; j++) {
				cout << Get2D<int>(i, j) << ", ";
			}
			cout << Get2D<int>(i, m_nNumElementsDimB - 1);
			cout << "), ";
		}
		cout << endl;
	}
}

BOOL CBitVector::IsEqual(CBitVector& vec) {
	if (vec.GetSize() != m_nByteSize) {
		return false;
	}

	BYTE* ptr = vec.GetArr();
	for (int i = 0; i < m_nByteSize; i++) {
		if (ptr[i] != m_pBits[i]) {
			return false;
		}
	}
	return true;
}

BOOL CBitVector::IsEqual(CBitVector& vec, int from, int to) {
	if (vec.GetSize() * 8 < to || m_nByteSize * 8 < to || from > to) {
		return false;
	}

	for (int i = from; i < to; i++) {
		if (vec.GetBit(i) != GetBit(i)) {
			return false;
		}
	}
	return true;
}

void CBitVector::XOR_no_mask(int p, int bitPos, int bitLen) {
	if (!bitLen)
		return;

	int i = bitPos >> 3, j = 8 - (bitPos & 0x7), k;

	m_pBits[i++] ^= (GetIntBitsFromLen(p, 0, min(j, bitLen)) << (8 - j)) & 0xFF;

	for (k = bitLen - j; k > 0; k -= 8, i++, j += 8) {
		m_pBits[i] ^= GetIntBitsFromLen(p, j, min(8, k));
	}
}

unsigned int CBitVector::GetInt(int bitPos, int bitLen) {
	int ret = 0, i = bitPos >> 3, j = (bitPos & 0x7), k;
	ret = (m_pBits[i++] >> (j)) & (GetMask(min(8, bitLen)));
	if (bitLen == 1)
		return ret;
	j = 8 - j;
	for (k = bitLen - j; i < (bitPos + bitLen + 7) / 8 - 1; i++, j += 8, k -= 8) {
		ret |= m_pBits[i] << j;
	}
	ret |= (m_pBits[i] & SELECT_BIT_POSITIONS[k]) << j; //for the last execution 0<=k<=8
	return ret;
}

void CBitVector::Transpose(int rows, int columns) {
#ifdef SIMPLE_TRANSPOSE
	SimpleTranspose(rows, columns);
#else
	EklundhBitTranspose(rows, columns);
#endif
}

void CBitVector::SimpleTranspose(int rows, int columns) {
	CBitVector temp(rows * columns);
	temp.Copy(m_pBits, 0, rows * columns / 8);
	for (int i = 0; i < rows; i++) {
		for (int j = 0; j < columns; j++) {
			SetBit(j * rows + i, temp.GetBit(i * columns + j));
		}
	}
}

//A transposition algorithm for bit-matrices of size 2^i x 2^i
void CBitVector::EklundhBitTranspose(int rows, int columns) {
	REGISTER_SIZE* rowaptr;	//ptr;
	REGISTER_SIZE* rowbptr;
	REGISTER_SIZE temp_row;
	REGISTER_SIZE mask;
	REGISTER_SIZE invmask;
	REGISTER_SIZE* lim;

	lim = (REGISTER_SIZE*) m_pBits + ceil_divide(rows * columns, 8);

	int offset = (columns >> 3) / sizeof(REGISTER_SIZE);
	int numiters = ceil_log2(min(rows, columns));
	int srcidx = 1, destidx;
	int rounds;
	int p;

	//If swapping is performed on bit-level
	for (int i = 0, j; i < LOG2_REGISTER_SIZE; i++, srcidx *= 2) {
		destidx = offset * srcidx;
		rowaptr = (REGISTER_SIZE*) m_pBits;
		rowbptr = rowaptr + destidx;

		//Preset the masks that are required for bit-level swapping operations
		mask = TRANSPOSITION_MASKS[i];
		invmask = ~mask;

		//If swapping is performed on byte-level reverse operations due to little-endian format.
		rounds = rows / (srcidx * 2);
		if (i > 2) {
			for (int j = 0; j < rounds; j++) {
				for (lim = rowbptr + destidx; rowbptr < lim; rowaptr++, rowbptr++) {
					temp_row = *rowaptr;
					*rowaptr = ((*rowaptr & mask) ^ ((*rowbptr & mask) << srcidx));
					*rowbptr = ((*rowbptr & invmask) ^ ((temp_row & invmask) >> srcidx));
				}
				rowaptr += destidx;
				rowbptr += destidx;
			}
		} else {
			for (int j = 0; j < rounds; j++) {
				for (lim = rowbptr + destidx; rowbptr < lim; rowaptr++, rowbptr++) {
					temp_row = *rowaptr;
					*rowaptr = ((*rowaptr & invmask) ^ ((*rowbptr & invmask) >> srcidx));
					*rowbptr = ((*rowbptr & mask) ^ ((temp_row & mask) << srcidx));
				}
				rowaptr += destidx;
				rowbptr += destidx;
			}
		}
	}

	for (int i = LOG2_REGISTER_SIZE, j, swapoffset = 1, dswapoffset; i < numiters; i++, srcidx *= 2, swapoffset = swapoffset << 1) {
		destidx = offset * srcidx;
		dswapoffset = swapoffset << 1;
		rowaptr = (REGISTER_SIZE*) m_pBits;
		rowbptr = rowaptr + destidx - swapoffset;

		rounds = rows / (srcidx * 2);
		for (int j = 0; j < rows / (srcidx * 2); j++) {
			for (p = 0, lim = rowbptr + destidx; p < destidx && rowbptr < lim; p++, rowaptr++, rowbptr++) {
				if ((p % dswapoffset >= swapoffset)) {
					temp_row = *rowaptr;
					*rowaptr = *rowbptr;
					*rowbptr = temp_row;
				}
			}
			rowaptr += destidx;
			rowbptr += destidx;
		}
	}

	if (columns > rows) {
		BYTE* tempvec = (BYTE*) malloc((rows * columns) / 8);
		memcpy(tempvec, m_pBits, ((rows / 8) * columns));

		rowaptr = (REGISTER_SIZE*) m_pBits;
		int rowbytesize = rows / 8;
		int rowregsize = rows / (sizeof(REGISTER_SIZE) * 8);
		for (int i = 0; i < columns / rows; i++) {
			rowbptr = (REGISTER_SIZE*) tempvec;
			rowbptr += (i * rowregsize);
			for (int j = 0; j < rows; j++, rowaptr += rowregsize, rowbptr += offset) {
				memcpy(rowaptr, rowbptr, rowbytesize);
			}
		}
		free(tempvec);
	}

	if (rows > columns) {
		BYTE* tempvec = (BYTE*) malloc((rows * columns) / 8);
		memcpy(tempvec, m_pBits, ((rows / 8) * columns));

		REGISTER_SIZE* rowaptr = (REGISTER_SIZE*) m_pBits;
		int colbytesize = columns / 8;
		int colregsize = columns / (sizeof(REGISTER_SIZE) * 8);
		int offset_cols = (columns * columns) / (sizeof(REGISTER_SIZE) * 8);

		for (int i = 0; i < columns; i++) {
			rowbptr = (REGISTER_SIZE*) tempvec;
			rowbptr += (i * colregsize);
			for (int j = 0; j < rows / columns; j++, rowaptr += colregsize, rowbptr += offset_cols) {
				memcpy(rowaptr, rowbptr, colbytesize);
			}
		}
		free(tempvec);
	}
}

