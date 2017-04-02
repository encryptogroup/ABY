/**
 \file 		cbitvector.h
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

#ifndef CBITVECTOR_H_
#define CBITVECTOR_H_

#include "typedefs.h"
#include "crypto/crypto.h"
#include <math.h>
#include <iostream>
#include <iomanip>

/** Deprecated. */
static const BYTE REVERSE_NIBBLE_ORDER[16] = { 0x0, 0x8, 0x4, 0xC, 0x2, 0xA, 0x6, 0xE, 0x1, 0x9, 0x5, 0xD, 0x3, 0xB, 0x7, 0xF };
/** Array which stores the bytes which are reversed. For example, the hexadecimal 0x01 is when reversed becomes 0x80.  */
static const BYTE REVERSE_BYTE_ORDER[256] = { 0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0, 0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0, 0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8,
		0x68, 0xE8, 0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8, 0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4, 0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4, 0x0C, 0x8C,
		0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC, 0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2, 0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2,
		0x72, 0xF2, 0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA, 0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA, 0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6, 0x16, 0x96,
		0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6, 0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE, 0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE, 0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1,
		0x61, 0xE1, 0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1, 0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9, 0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9, 0x05, 0x85,
		0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5, 0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5, 0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED, 0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD,
		0x7D, 0xFD, 0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3, 0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3, 0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB, 0x1B, 0x9B,
		0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB, 0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7, 0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7, 0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF,
		0x6F, 0xEF, 0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF };

/**
	This array is used by \link XORBits(BYTE* p, int pos, int len) \endlink and \link SetBits(BYTE* p, uint64_t pos, uint64_t len) \endlink
    method for lower bit mask.
*/
static const BYTE RESET_BIT_POSITIONS[9] = { 0x00, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF };
/**
	This array is used by \link XORBits(BYTE* p, int pos, int len) \endlink and \link SetBits(BYTE* p, uint64_t pos, uint64_t len) \endlink
    method for upper bit mask.
*/
static const BYTE RESET_BIT_POSITIONS_INV[9] = { 0x00, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE, 0xFF };

/** This array is used by \link GetBits(BYTE* p, int pos, int len) \endlink method for lower bit mask. */
static const BYTE GET_BIT_POSITIONS[9] = { 0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80, 0x00 };

/** This array is used by \link GetBits(BYTE* p, int pos, int len) \endlink method for upper bit mask. */
static const BYTE GET_BIT_POSITIONS_INV[9] = { 0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01, 0x00 };

/** Deprecated */
static const int INT_MASK[8] = { 0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01 };

/** Deprecated */
static const int FIRST_MASK_SHIFT[8] = { 0xFF00, 0x7F80, 0x3FC0, 0x1FE0, 0x0FF0, 0x07F8, 0x03FC, 0x01FE };
/**
	This array is used for masking bits and extracting a particular positional bit from the provided byte array.
	This array is used by \link GetBit(int idx) \endlink method.
*/
static const BYTE MASK_BIT[8] = { 0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1 };

/**
	This array is used for extracting a particular positional bit from the provided byte array without masking.
	This array is used by \link GetBitNoMask(int idx) \endlink method.
*/
static const BYTE BIT[8] = { 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80 };

/**
	This array is used for masking bits and setting a particular positional bit from the provided byte array in the CBitVector.
	This array is used by \link SetBit(int idx, BYTE b) \endlink and \link ANDBit(int idx, BYTE b) \endlink methods.
*/
static const BYTE CMASK_BIT[8] = { 0x7f, 0xbf, 0xdf, 0xef, 0xf7, 0xfb, 0xfd, 0xfe };

/**
	This array is used for setting a particular positional bit from the provided byte array without masking in the CBitVector.
	This array is used by \link SetBitNoMask(int idx, BYTE b) \endlink and \link ANDBitNoMask(int idx, BYTE b) \endlink methods.
*/
static const BYTE C_BIT[8] = { 0xFE, 0xFD, 0xFB, 0xF7, 0xEF, 0xDF, 0xBF, 0x7F };
/** Deprecated */
static const BYTE MASK_SET_BIT[2][8] = { { 0, 0, 0, 0, 0, 0, 0, 0 }, { 0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1 } };



/**
	This array is used for masking bits and setting a particular positional bit from the provided byte array in the CBitVector.
	This array is used by \link SetBit(int idx, BYTE b) \endlink and \link XORBit(int idx, BYTE b) \endlink methods.
*/
static const BYTE MASK_SET_BIT_C[2][8] = { { 0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1 }, { 0, 0, 0, 0, 0, 0, 0, 0 } };

/**
	This array is used for setting a particular positional bit from the provided byte array without masking in the CBitVector.
	This array is used by \link SetBitNoMask(int idx, BYTE b) \endlink and \link XORBitNoMask(int idx, BYTE b) \endlink methods.
*/
static const BYTE SET_BIT_C[2][8] = { { 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80 }, { 0, 0, 0, 0, 0, 0, 0, 0 } };

const BYTE SELECT_BIT_POSITIONS[9] = { 0x00, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF };

#ifdef MACHINE_SIZE_32
static const REGISTER_SIZE TRANSPOSITION_MASKS[6] =
{	0x55555555, 0x33333333, 0x0F0F0F0F, 0x00FF00FF, 0x0000FFFF};
static const REGISTER_SIZE TRANSPOSITION_MASKS_INV[6] =
{	0xAAAAAAAA, 0xCCCCCCCC, 0xF0F0F0F0, 0xFF00FF00, 0xFFFF0000};
#else
#ifdef MACHINE_SIZE_64
/** Transposition mask used for Eklund Bit Matrix Transposition.*/
static const REGISTER_SIZE TRANSPOSITION_MASKS[6] = { 0x5555555555555555, 0x3333333333333333, 0x0F0F0F0F0F0F0F0F, 0x00FF00FF00FF00FF, 0x0000FFFF0000FFFF, 0x00000000FFFFFFFF };
static const REGISTER_SIZE TRANSPOSITION_MASKS_INV[6] = { 0xAAAAAAAAAAAAAAAA, 0xCCCCCCCCCCCCCCCC, 0xF0F0F0F0F0F0F0F0, 0xFF00FF00FF00FF00, 0xFFFF0000FFFF0000, 0xFFFFFFFF00000000 };
#else
#endif
#endif

static const size_t SHIFTVAL = 3;

/** Class which defines the functionality of storing C-based Bits in vector type format.*/
class CBitVector {
public:

	//Constructor code begins here...

	/** Constructor which initializes the member variables bit pointer and size to NULL and zero respectively. */
	CBitVector() {
		Init();
	}
	/**
	 	 Overloaded constructor of class \link CBitVector \endlink which calls internally \link Create(uint64_t bits) \endlink
	 	 \param  bits	 - It is the number of bits which will be used to allocate the CBitVector with. For more info on how these bits are allocated refer to \link Create(uint64_t bits) \endlink
	 */
	CBitVector(uint32_t bits) {
		Init();
		Create(bits);
	}
	/**
	 	Overloaded constructor of class \link CBitVector \endlink which calls internally \link Create(uint64_t bits,crypto* crypt) \endlink
	 	\param  bits	 - It is the number of bits which will be used to allocate the CBitVector with. For more info on how these bits are allocated refer to \link Create(uint64_t bits,crypto* crypt) \endlink
	 	\param  crypt 	 - This object from crypto class is used to generate pseudo random values for the cbitvector.
	 */
	CBitVector(uint32_t bits, crypto* crypt) {
		Init();
		Create(bits, crypt);
	}
	//Constructor code ends here...

	//Basic Primitive function of allocation and deallocation begins here.
	/**
	 	 Function which gets called initially when the cbitvector object is created. This method is mostly called from constructor of CBitVector class.
	 	 The method sets bit pointer and size to NULL and zero respectively.
	*/
	void Init() {
		m_pBits = NULL;
		m_nByteSize = 0;
	}

	/**
			Destructor which internally calls the delCBitVector for deallocating the space. This method internally calls
			\link delCBitVector() \endlink.
	*/
	~CBitVector(){
		delCBitVector();
	};

	/**
		This method is used to deallocate the bit pointer and size explicitly. This method needs to be called by the programmer explicitly.
	*/
	void delCBitVector() {
		if (( m_nByteSize > 0 )&& (m_pBits != NULL)) {
			free(m_pBits);
		}
		m_nByteSize = 0;
		m_pBits = NULL;
	}
	//Basic Primitive function of allocation and deallocation ends here.


	//Create function supported by CBitVector starts here...
	/**
		This method generates random values and assigns it to the bitvector using crypto object. If the bits provided in the params are greater
		than the bit size of the bitvector, then the bit vector is recreated with new bit size and filled in with random values.

		\param  bits	 - It is the number of bits which will be used to allocate and assign random values of the CBitVector with. For more info on how these bits are allocated refer to \link Create(uint64_t bits) \endlink
		\param	crypt	 - It is the crypto class object which is used to generate random values for the bit size.
	*/
	void FillRand(uint32_t bits, crypto* crypt);



	/* Create in bits and bytes */

	/**
		This method is used to create the CBitVector with the provided bits. The method creates a bit vector with a size close to AES Bitsize.
		For example, if bit size provided is 110. After this method is called it will be 128 bits. It will perform a ceil of provided_bit_size
		to AES bit size and multiply that ceiled value with AES bits size. (For reference, AES Bit size is taken as 128 bits)

		\param  bits	 - It is the number of bits which will be used to allocate the CBitVector with.
	*/
	void Create(uint64_t bits);

	//void Create(int bits) {Create((uint64_t) bits);}

	/**
		This method is used to create the CBitVector with the provided byte size. The method creates a bit vector with a size close to AES Bytesize.
		For example, if byte size provided is 9. After this method is called it will be 16 bytes. It will perform a ceil of provided_byte_size
		to AES byte size and multiply that ceiled value with AES byte size. (For reference, AES Byte size is taken as 16 bytes). Internally, this method
		calls \link Create(uint64_t bits) \endlink. Therefore, for further info please refer to the internal method provided.

		\param  bytes	 - It is the number of bytes which will be used to allocate the CBitVector with.
	*/
	void CreateBytes(uint64_t bytes) {
		Create(bytes << 3);
	}
	/**
		This method is used to create the CBitVector with the provided byte size and fills it with random data from the crypt object. The method creates a
		bit vector with a size close to AES Bytesize. For example, if byte size provided is 9. After this method is called it will be 16 bytes. It will perform a ceil of provided_byte_size
		to AES byte size and multiply that ceiled value with AES byte size. (For reference, AES Byte size is taken as 16 bytes). Internally, this method
		calls \link Create(uint64_t bits, crypto* crypt) \endlink. Therefore, for further info please refer to the internal method provided.

		\param  bytes	 - It is the number of bytes which will be used to allocate the CBitVector with.
		\param  crypt	 - Reference to a crypto object from which fresh randomness is sampled
	*/
	void CreateBytes(uint64_t bytes, crypto* crypt) {
		Create(bytes << 3, crypt);
	}
	/**
		This method is used to create the CBitVector with the provided bits and set them to value zero. The method creates a bit vector with a size close to AES Bitsize.
		And performs an assignment of zero to each bit being allocated. Internally, this method calls \link Create(uint64_t bits) \endlink. Therefore, for further info
		please refer to the internal method provided.

		\param  bits	 - It is the number of bits which will be used to allocate and assign zero values of the CBitVector with.
	*/
	void CreateZeros(uint64_t bits) {
		Create(bits);
		memset(m_pBits, 0, m_nByteSize);
	}

	/**
		This method is used to create the CBitVector with the provided bits and set them to some random values. The method creates a bit vector with a size close to AES Bitsize.
		And performs an assignment of random values to each bit being allocated. Internally, this method calls \link Create(uint64_t bits) \endlink and
		\link FillRand(uint32_t bits, crypto* crypt) \endlink. Therefore, for further info please refer to the internal method provided.

		\param  bits	 - It is the number of bits which will be used to allocate and assign random values of the CBitVector with.
		\param	crypt	 - It is the crypto class object which is used to generate random values for the bit size.
	*/
	void Create(uint64_t bits, crypto* crypt);


	/**
		This method is used create the CBitVector with the provided number of elements and element length. This method basically creates a 1-dimensional array/vector with the provided
		element size and number of elements. This method internally calls \link Create(uint64_t bits) \endlink with arguments as elementlength*numelements.
		\param numelements		- The number of elements in the 1-dimensional array/vector which gets created.
		\param elementlength	- The size of element in the provided cbitvector.
	*/
	void Create(uint64_t numelements, uint64_t elementlength);

	/**
		This method is used create the CBitVector with the provided number of elements and element length and then assign random values to them. This method basically creates
		a 1-dimensional array/vector with the provided element size and number of elements and assign some random values based on crypt object provided. This method internally
		calls \link Create(uint64_t bits, crypto* crypt) \endlink for creation of 1-d vector.
		\param numelements		- The number of elements in the 1-dimensional array/vector which gets created.
		\param elementlength	- The size of element in the provided cbitvector.
		\param crypt			- It is the crypto class object which is used to generate random values for the provided bit size.
	*/
	void Create(uint64_t numelements, uint64_t elementlength, crypto* crypt);

	/**
		This method is used create the CBitVector with the provided number of elements of 2 dimensions and element length. This method basically creates a 2-dimensional array/vector
		with the provided element size and number of elements in two dimensions. This method internally calls \link Create(uint64_t bits) \endlink with arguments as
		elementlength*numelementsDimA*numelementsDimB.
		\param numelementsDimA		- The number of elements in the 1st-dimension of the 2d array/vector which gets created.
		\param numelementsDimB		- The number of elements in the 2nd-dimension of the 2d array/vector which gets created.
		\param elementlength		- The size of element in the provided cbitvector.
	*/
	void Create(uint64_t numelementsDimA, uint64_t numelementsDimB, uint64_t elementlength);
	/**
		This method is used create the CBitVector with the provided number of elements of 2 dimensions and element length, and then assign random values to them. This method basically
		creates a 2-dimensional array/vector with the provided element size and number of elements in two dimensions  and assign some random values based on crypt object provided.
		This method internally calls \link Create(uint64_t bits, crypto* crypt) \endlink.
		\param numelementsDimA		- The number of elements in the 1st-dimension of the 2d array/vector which gets created.
		\param numelementsDimB		- The number of elements in the 2nd-dimension of the 2d array/vector which gets created.
		\param elementlength		- The size of element in the provided cbitvector.
		\param crypt				- It is the crypto class object which is used to generate random values for the provided bit size.
	*/
	void Create(uint64_t numelementsDimA, uint64_t numelementsDimB, uint64_t elementlength, crypto* crypt);
	//Create function supported by CBitVector ends here...



	/*
	 * Management operations
	 */

	/**
		This method is used to resize the bytes allocated to CBitVector with newly provided size. And also accommodate the data from previous allocation to new one.
		\param newSizeBytes		-	This variable provides the new size to which the cbitvector needs to be modified to user's needs.
	*/
	void ResizeinBytes(uint64_t newSizeBytes);

	/**
		This method is used to reset the values in the given CBitVector. This method sets all bit values to zeros. This is a slight variant of the method
		\link CreateZeros(uint64_t bits) \endlink. The create method mentioned above allocates and sets value to zero. Whereas the provided method only
		sets the value to zero.
	*/
	void Reset() {
		memset(m_pBits, 0, m_nByteSize);
	}

	/**
		This method is used to reset the values in the given CBitVector for specific byte range.
		\param 	frombyte	-	The source byte position from which the values needs to be reset.
		\param 	tobyte		-	The destination byte position until which the values needs to be reset to.
	*/
	void ResetFromTo(int frombyte, int tobyte) {
		assert(frombyte <= tobyte);
		assert(tobyte < m_nByteSize);
		memset(m_pBits + frombyte, 0, tobyte - frombyte);
	}

	/**
		This method sets all bit position values in a CBitVector to One.
	*/
	void SetToOne() {
		memset(m_pBits, 0xFF, m_nByteSize);
	}

	/**
		This method sets all bits in the CBitVector to the inverse
	*/
	void Invert();


	/**
		This is a getter method which returns the size of the CBitVector in bytes.
		\return the byte size of CBitVector.
	*/
	int GetSize() {
		return m_nByteSize;
	}

	/**
		This method checks if two CBitVectors are equal or not.
		\param	vec		-		Vector to be checked with current one for the case of equality.
		\return	boolean value which says whether it is equal or not.
	*/
	BOOL IsEqual(CBitVector& vec);

	/**
		This method checks if two CBitVectors are equal or not for a given range of bit positions.
		\param	vec		-		Vector to be checked with current one for the case of equality.
		\param  from	-		Bit Position from which the vectors need to be checked for equality.
		\param	to	 	-		Bit Position until which the vectors need to be checked for equality.
		\return	boolean value which says whether the vectors are equal or not in the provided range of bits.
	*/
	BOOL IsEqual(CBitVector& vec, int from, int to);

	/**
		This method sets the element length of the CBitVector. It can be used to modify the object size in a CBitVector when
		around with the multi dimensional arrays/vectors.
		\param	elelen	-		New element length which can be used to set the object size in a CBitVector.
	*/
	void SetElementLength(int elelen) {
		m_nElementLength = elelen;
	}


	/**
		This method gets the element length of the CBitVector.
		\return element length of the elements in CBitVector.
	*/
	uint64_t GetElementLength() {
		return m_nElementLength;
	}

	/*
	 * Copy operations
	 */

	/**
		This method is used to copy the provided CBitVector to itself. It internally calls
		\link Copy(BYTE* p, int pos, int len) \endlink for copying bytewise.
		\param	vec		- 		The vector from which the copying needs to be performed.
	*/
	void Copy(CBitVector& vec) {
		Copy(vec.GetArr(), 0, vec.GetSize());
	}
	/**
		This method is used to copy the provided CBitVector to itself for a given range. It internally calls \link Copy(BYTE* p, int pos, int len) \endlink
		for copying bytewise. Copying is done in a slightly different way. Here the range is pos and len. The offset is defined for the base vector and not
		for the copying vector. So if the method is called as B.Copy(A,5,10) then, values of vector A will be copied from first index location for length 10
		to the vector B from position 5 for length 10. Unlike copying values from 5 position in vector A to vector B for length 10.
		\param	vec		- 		The vector from which the copying needs to be performed.
		\param	pos		- 		The positional offset for copying into current vector.
		\param	len		-		Length or amount of values to be copied to the current vector from provided vector.
	*/
	void Copy(CBitVector& vec, int pos, int len) {
		Copy(vec.GetArr(), pos, len);
	}

	/**
		This method is used to copy the current CBitVector with some ByteLocation with positional shift and length. This method is the base method for methods
		\link Copy(CBitVector& vec, int pos, int len) \endlink and \link Copy(CBitVector& vec) \endlink.
		\param	p		-		Pointer to the byte location to be copied to the CBitVector.
		\param	pos		-		Positional offset for copying into current CBitVector.
		\param	len		-  		Length or amount of values to be copied to the current vector from provided byte location.
	*/
	void Copy(BYTE* p, int pos, int len);

	/** Deprecated */
	void XOR_no_mask(int p, int bitPos, int bitLen);

	/** Deprecated */
	unsigned int GetInt(int bitPos, int bitLen);
#define GetIntBitsFromLen(x, from, len) 	( ( (x & ( ( (2<<(len))-1) << from )) >> from) & 0xFF)
#define GetMask(len) 				(( (1<<(len))-1))

	/**
		This method performs OR operation bytewise with the current CBitVector at the provided byte position with another Byte object.
		\param	pos		- 		Byte position in the CBitVector which is used to perform OR operation with.
		\param	p		-		Byte with which the OR operation is performed to get the result.

	*/
	void ORByte(int pos, BYTE p);

	/*
	 * Bitwise operations
	 */

	/**
		This method gets the bit in the provided index by using the maskbits. The maskbits brings the concept of
		endianness in the vector. In this method MASK_BIT is used to  extract the bits which are assumed to be
		organized in Little Endian form.
		\param	idx		-		Bit Index which needs to be fetched from the CBitVector.
		\return The byte which has got just the bit in it.
	*/
	BYTE GetBit(int idx) {
		assert(idx < (m_nByteSize << 3));
		return !!(m_pBits[idx >> 3] & MASK_BIT[idx & 0x7]);
	}
	/**
		This method sets the bit in the provided index by using the maskbits and the provided bit. The maskbits brings the concept of
		endianness in the vector. In this method C_MASK_BIT is used to figure out the bits which are assumed to be
		organized in Little Endian form.
		\param	idx		-		Bit Index which needs to be written to in the CBitVector.
		\param	b		-		The bit which being written in the provided index.
	*/
	void SetBit(int idx, BYTE b) {
		assert(idx < (m_nByteSize << 3));
		m_pBits[idx >> 3] = (m_pBits[idx >> 3] & CMASK_BIT[idx & 0x7]) | MASK_SET_BIT_C[!(b & 0x01)][idx & 0x7];
	}
	/* Deprecated */
	/**
		This method XORs the bit in the provided index by using the maskbits and the provided bit. The maskbits brings the concept of
		endianness in the vector. In this method MASK_SET_BIT is used to extract and set the bits which are assumed to be
		organized in Little Endian form.
		\param	idx		-		Bit Index which needs to be XORed to in the CBitVector.
		\param	b		-		The bit which being XORed in the provided index.
	*/
	void XORBit(int idx, BYTE b) {
		assert(idx < (m_nByteSize << 3));
		m_pBits[idx >> 3] ^= MASK_SET_BIT_C[!(b & 0x01)][idx & 0x7];
	}

	/* Deprecated */
	/**
		This method ANDs the bit in the provided index by using the maskbits and the provided bit. The maskbits brings the concept of
		endianness in the vector. In this method C_MASK_BIT is used to extract and set the bits which are assumed to be
		organized in Little Endian form.
		\param	idx		-		Bit Index which needs to be ANDed to in the CBitVector.
		\param	b		-		The bit which being ANDed in the provided index.
	*/
	void ANDBit(int idx, BYTE b) {
		assert(idx < (m_nByteSize << 3));
		if (!b)
			m_pBits[idx >> 3] &= CMASK_BIT[idx & 0x7];
	}

	//used to access bits in the regular order

	/**
		This method gets the bit in the provided index without using the maskbits. The maskbits brings the concept of
		endianness in the vector. In this method mask bits are not used so the vector is treated in Big Endian form.
		\param	idx		-		Bit Index which needs to be fetched from the CBitVector.
		\return The byte which has got just the bit in it.
	*/
	BYTE GetBitNoMask(uint64_t idx) {
		assert(idx < (m_nByteSize << 3));
		return !!(m_pBits[idx >> 3] & BIT[idx & 0x7]);
	}

	/**
		This method sets the bit in the provided index without using the maskbits. The maskbits brings the concept of
		endianness in the vector. In this method mask bits are not used so the vector is treated in Big Endian form.
		\param	idx		-		Bit Index which needs to be written to in the CBitVector.
		\param	b		-		The bit which being written in the provided index.
	*/
	void SetBitNoMask(int idx, BYTE b) {
		assert(idx < (m_nByteSize << 3));
		m_pBits[idx >> 3] = (m_pBits[idx >> 3] & C_BIT[idx & 0x7]) | SET_BIT_C[!(b & 0x01)][idx & 0x7];
	}

	/**
		This method XORs the bit in the provided index without using the maskbits. The maskbits brings the concept of
		endianness in the vector. In this method mask bits are not used so the vector is treated in Big Endian form.
		\param	idx		-		Bit Index which needs to be XORed to in the CBitVector.
		\param	b		-		The bit which being XORed in the provided index.
	*/
	void XORBitNoMask(int idx, BYTE b) {
		assert(idx < (m_nByteSize << 3));
		m_pBits[idx >> 3] ^= SET_BIT_C[!(b & 0x01)][idx & 0x7];
	}

	/* Deprecated */
	/**
		This method ANDs the bit in the provided index without using the maskbits. The maskbits brings the concept of
		endianness in the vector. In this method mask bits are not used so the vector is treated in Big Endian form.
		\param	idx		-		Bit Index which needs to be ANDed to in the CBitVector.
		\param	b		-		The bit which being ANDed in the provided index.
	*/
	void ANDBitNoMask(int idx, BYTE b) {
		assert(idx < (m_nByteSize << 3));
		if (!b)
			m_pBits[idx >> 3] &= C_BIT[idx & 0x7];
	}

	/*
	 * Single byte operations
	 */

	/**
		This method sets a byte in a given index of the CBitVector with the provided Byte.
		\param	idx		-	Index where the byte needs to be set.
		\param	p		-	Byte which needs to be copied to.
	*/
	void SetByte(int idx, BYTE p) {
		assert(idx < m_nByteSize);
		m_pBits[idx] = p;
	}

	/**
		This method returns the byte at the given index in the CBitVector. Here the index is w.r.t bytes.
		\param	idx		-	Index of the byte which needs to be returned from the CBitVector.
		\return Byte is returned from CBitVector at the given index.
	*/
	BYTE GetByte(int idx) {
		assert(idx < m_nByteSize);
		return m_pBits[idx];
	}

	/**
		Not Used Currently in Framework.
		This method performs XOR operation at the given index in the CBitVector with a provided Byte.
		\param	idx		-	Index of the byte which needs to be XORed inside the CBitVector.
		\param	b		- 	Byte to be XORed with the CBitVector.
	*/
	void XORByte(int idx, BYTE b) {
		assert(idx < m_nByteSize);
		m_pBits[idx] ^= b;
	}
	/**
		This method performs AND operation at the given index in the CBitVector with a provided Byte.
		\param	idx		-	Index of the byte which needs to be ANDed inside the CBitVector.
		\param	b		- 	Byte to be ANDed with the CBitVector.
	*/
	void ANDByte(int idx, BYTE b) {
		assert(idx < m_nByteSize);
		m_pBits[idx] &= b;
	}

	/*
	 * Get Operations
	 */

	/**
		This method gets elements from the CBitVector bitwise from a given offset for a given length. And stores the result
		in the provided byte pointer. This method is used by the generic method \link Get(int pos, int len) \endlink
		\param	p		-	The resulting bits for the given range in the CBitVector is stored in the byte pointer p.
		\param	pos		-	The positional offset in the CBitVector from which the data needs to obtained.
		\param	len		- 	The range limit of obtaining the data from the CBitVector.
	*/
	void GetBits(BYTE* p, int pos, int len);

	/**
		This method gets elements from the CBitVector bytewise from a given offset for a given length. And stores the result
		in the provided byte pointer.
		\param	p		-	The resulting bits for the given range in the CBitVector is stored in the byte pointer p.
		\param	pos		-	The positional offset in the CBitVector from which the data needs to obtained.
		\param	len		- 	The range limit of obtaining the data from the CBitVector.
	*/
	void GetBytes(BYTE* p, int pos, int len);

	/**
		Generic method which performs the operation of getting bytes from source for the given limit.
	*/
	template<class T> void GetBytes(T* dst, T* src, T* lim);

	/**
		Generic method which performs the operation of getting values from a CBitVector for a given bit position and length.
		This method internally calls \link GetBits(BYTE* p, int pos, int len) \endlink.
		\param	pos		-	The positional offset in the CBitVector from which the data needs to obtained.
		\param	len		- 	The range limit of obtaining the data from the CBitVector.
		\return	returns the value/values for the provided range.
	*/
	template<class T> T Get(int pos, int len) {
		assert(len <= sizeof(T) * 8);
		T val = 0;
		GetBits((BYTE*) &val, pos, len);
		return val;
	}

	/*
	 * Set Operations
	 */
	/**
		The method for setting CBitVector for a given bit range with offset and length in unsigned 64bit integer format. This method
		is called from \link SetBits(BYTE* p, int pos, int len) \endlink and \link Set(T val, int pos, int len) \endlink.
		\param	p		-	Byte array passed to be set to the current CBitVector.
		\param	pos		-	Positional offset in the CBitVector, where data will be set from the provided byte array.
		\param	len		-   The range limit of obtaining the data from the CBitVector.
	*/
	void SetBits(BYTE* p, uint64_t pos, uint64_t len);

	/**
		The method for setting CBitVector for a given bit range with offset and length in simple integer format. This method internally
		calls \link SetBits(BYTE* p, uint64_t pos, uint64_t len) \endlink.
		\param	p		-	Byte array passed to be set to the current CBitVector.
		\param	pos		-	Positional offset in the CBitVector, where data will be set from the provided byte array.
		\param	len		-   The range limit of obtaining the data from the CBitVector.
	*/
	void SetBits(BYTE* p, int pos, int len) {
		SetBits(p, (uint64_t) pos, (uint64_t) len);
	}

	/**
		The method for setting CBitVector for a given bit range with offsets and length with another Byte Array.
		\param	p		-	Byte array passed to be set with the current CBitVector.
		\param	ppos	-	Positional offset in the Byte Array.
		\param	pos		-	Positional offset in the CBitVector, where data will be set from the provided byte array.
		\param	len		-	The range limit of obtaining the data from the CBitVector.
	 */
	void SetBitsPosOffset(BYTE* p, uint64_t ppos, uint64_t pos, uint64_t len);

	/**
		The method for setting CBitVector for a given byte range with offset and length. This method internally calls the method
		\link SetBytes(T* dst, T* src, T* lim) \endlink.
		\param	src		-	Byte array passed to be set to the current CBitVector.
		\param	pos		-	Byte position offset in the CBitVector, where data will be set from the provided byte array.
		\param	len		-   The number of bytes to be set.
	*/
	void SetBytes(const BYTE* src, const uint64_t pos, const uint64_t len);

	/**
		Generic method which performs the operation of setting bytes from source for the given limit. This method is called from
		\link SetBytes(BYTE* p, int pos, int len) \endlink.
	*/
	template<class T> void SetBytes(T* dst, const  T* src, const T* lim);

	/**
		This method sets the values in a given byte range to Zero in the current CBitVector.
		\param	bytepos		-	Byte Positional offset in the CBitVector.
		\param	bytelen		-	Byte Length in the CBitVector until which the value needs to be set to zero.
	*/
	void SetBytesToZero(int bytepos, int bytelen);

	/**
		Generic method which performs the operation of setting values to a CBitVector for a given bit position and length.
		This method internally calls \link SetBits(BYTE* p, uint64_t pos, uint64_t len) \endlink.
		\param	pos		-	The positional offset in the CBitVector from which the data needs to obtained.
		\param	len		- 	The range limit of obtaining the data from the CBitVector.
	*/
	template<class T> void Set(T val, int pos, int len) {
		assert(len <= sizeof(T) * 8);
		SetBits((BYTE*) &val, (uint64_t) pos, (uint64_t) len);
	}

	/**
		This method sets the values in a given bit range to Zero in the current CBitVector.
		\param	bitpos		-	Bit Positional offset in the CBitVector.
		\param	bitlen		-	Bit Length in the CBitVector until which the value needs to be set to zero.
	*/
	void SetBitsToZero(int bitpos, int bitlen);

	/**
		Sets the bits from position pos to position pos+bitlen from the CBitVector to the value of src rotated
		by rot_val bits to the left.
		\param	src			-	Source value to which the CBitVector is set
		\param	rot_val		-	Bit value by which the source value is cyclic left rotated
		\param 	pos			- 	Start bit position to which the src value is copied into the CBitVector
		\param 	bitlen		-	Number of bits to copy into the CBitVector
	*/
	void SetBitsRotL(uint8_t* src, uint32_t rot_val, uint32_t pos, uint32_t bitlen);

	/*
	 * XOR Operations
	 */

	/**
		This method performs XOR operation from a given position in the CBitVector with a provided Byte Array with a length.
		This method is called from \link XORBytes(BYTE* p, int len) \endlink. This method internally calls \link XORBytes(T* dst, T* src, T* lim) \endlink.
		\param	p		- 		Byte Array to be XORed with the CBitVector range.
		\param	pos		-		Positional offset for XORing into current CBitVector.
		\param	len		-  		Length or amount of values to be XORed to the current vector from provided byte location.
	*/
	void XORBytes(BYTE* p, int pos, int len);
	/**
		This method performs XOR operation for a given length in the CBitVector with a provided Byte Array.	This method internally calls
		\link XORBytes(BYTE* p, int pos, int len) \endlink.
		\param	p		- 		Byte Array to be XORed with the CBitVector range.
		\param	len		-  		Length or amount of values to be XORed to the current vector from provided byte location.
	*/
	void XORBytes(BYTE* p, int len) {
		XORBytes(p, 0, len);
	}

	/**
	 	Not Used in the Framework.
		This method performs XOR operation from a given position in the CBitVector with another CBitVector with a length.
		This method internally calls \link XORBytes(BYTE* p, int pos, int len) \endlink.
		\param	vec		- 		Provided Array to be XORed with the CBitVector.
		\param	pos		-		Positional offset for XORing into current CBitVector.
		\param	len		-  		Length or amount of values to be XORed to the current vector from provided byte location.
	*/
	void XORVector(CBitVector &vec, int pos, int len) {
		XORBytes(vec.GetArr(), pos, len);
	}

	/**
		Generic method which is used to XOR bit wise the CBitVector. This method internally calls
		\link XORBits(BYTE* p, int pos, int len) \endlink.
	*/
	template<class T> void XOR(T val, int pos, int len) {
		assert(len <= sizeof(T) * 8);
		XORBits((BYTE*) &val, pos, len);
	}

	/**
		The method for XORing CBitVector for a given bit range with offset and length. This method is called from
		\link XOR(T val, int pos, int len) \endlink.
		\param	p		-	Byte array passed to be XORed with the current CBitVector.
		\param	pos		-	Positional offset in the CBitVector, where data will be XORed from the provided byte array.
		\param	len		-   The range limit of obtaining the data from the CBitVector.
	*/
	void XORBits(BYTE* p, int pos, int len);

	/**
		The method for XORing CBitVector for a given bit range with offsets and length with another Byte Array.
		\param	p		-	Byte array passed to be XORed with the current CBitVector.
		\param	ppos	-	Positional offset in the Byte Array.
		\param	pos		-	Positional offset in the CBitVector, where data will be XORed from the provided byte array.
		\param	len		-   The range limit of obtaining the data from the CBitVector.
	*/
	void XORBitsPosOffset(BYTE* p, int ppos, int pos, int len);

	/**
		Generic method which is used to XOR byte wise the CBitVector. This method is called from
		\link XORBytes(BYTE* p, int pos, int len) \endlink.
	*/
	template<class T> void XORBytes(T* dst, T* src, T* lim);

	/**
		Set the value of this CBitVector to this XOR b
		\param	b		-	Pointer to a CBitVector which is XORed on this CBitVector
	*/
	void XOR(CBitVector* b);

	/** Deprecated */
	void XORRepeat(BYTE* p, int pos, int len, int num);

	/**
		This method performs XOR operation from a given position in the CBitVector with a provided Byte Array with a length.
		The XORing is performed in a slightly different way. The byte array is reversed before it is XORed with the CBitVector.
		This method is called from \link XORBytes(BYTE* p, int len) \endlink. This method internally calls \link XORBytes(T* dst, T* src, T* lim) \endlink.
		\param	p		- 		Byte Array to be XORed with the CBitVector range.
		\param	pos		-		Positional offset for XORing into current CBitVector.
		\param	len		-  		Length or amount of values to be XORed to the current vector from provided byte location.
	*/
	void XORBytesReverse(BYTE* p, int pos, int len);

	/*
	 * AND Operations
	 */

	/**
		This method performs AND operation from a given position in the CBitVector with a provided Byte Array with a length.
		This method internally calls \link ANDBytes(T* dst, T* src, T* lim) \endlink.
		\param	p		- 		Byte Array to be ANDed with the CBitVector range.
		\param	pos		-		Positional offset for ANDing into current CBitVector.
		\param	len		-  		Length or amount of values to be ANDed to the current vector from provided byte location.
	*/
	void ANDBytes(BYTE* p, int pos, int len);

	/**
		Generic method which is used to AND byte wise the CBitVector. This method is called from
		\link ANDBytes(BYTE* p, int pos, int len) \endlink.
	*/
	template<class T> void ANDBytes(T* dst, T* src, T* lim);

	/*
	 * Set operations
	 */
	/**
		This method is used to set and XOR a CBitVector with a byte array and then XOR it with another byte array
		for a given range. This method internally calls \link Copy(BYTE* p, int pos, int len) \endlink and
		\link XORBytes(BYTE* p, int pos, int len) \endlink.
		\param	p		-		Pointer to the byte location to be copied to the CBitVector.
		\param 	q		-		Pointer to the byte location with which the CBitVector is XORed with.
		\param	pos		-		Positional offset for copying and XORing into current CBitVector.
		\param	len		-  		Length or amount of values to be copied and XORed to the current vector from provided byte location.
	*/
	void SetXOR(BYTE* p, BYTE* q, int pos, int len);

	/**
		This method is used to set and AND a CBitVector with a byte array and then AND it with another byte array
		for a given range. This method internally calls \link Copy(BYTE* p, int pos, int len) \endlink and
		\link ANDBytes(BYTE* p, int pos, int len) \endlink.
		\param	p		-		Pointer to the byte location to be copied to the CBitVector.
		\param 	q		-		Pointer to the byte location with which the CBitVector is ANDed with.
		\param	pos		-		Positional offset for copying and ANDing into current CBitVector.
		\param	len		-  		Length or amount of values to be copied and ANDed to the current vector from provided byte location.
	*/
	void SetAND(BYTE* p, BYTE* q, int pos, int len);

	/**
		Set the value of this CBitVector to this AND b
		\param	b		-	Pointer to a CBitVector which is ANDed on this CBitVector
	*/
	void AND(CBitVector* b);

	/**
		Cyclic shift left by pos positions
		\param	pos		-	the left shift value
	*/
	void CLShift(uint64_t pos);


	/*
	 * Buffer access operations
	 */

	/**
		This method returns CBitVector in byte array format. This is very widely used method.
	*/
	BYTE* GetArr() {
		return m_pBits;
	}

	/**
		This method is used to attach a new buffer into the CBitVector provided as arguments to this method.
		\param	p		-		Pointer to the byte location to be attached to the CBitVector.
		\param  size	-		Number of bytes attached from the provided buffer.
	*/
	void AttachBuf(BYTE* p, uint64_t size = -1) {
		m_pBits = p;
		m_nByteSize = size;
	}


	/**
		This method is used to detach the buffer from the CBitVector. */
	void DetachBuf() {
		m_pBits = NULL;
		m_nByteSize = 0;
	}

	/*
	 * Print Operations
	 */

	/**
		This method prints the CBitVector bitwise for provided bit range. This method internally calls \link  GetBitNoMask(int idx) \endlink.
		This method is called from \link PrintBinary() \endlink.
		\param	fromBit			-		The bit from which the printing starts in a CBitVector.
		\param	toBit			-		The bit until which the printing in a CBitVector is done.
	*/
	void Print(int fromBit, int toBit);

	/**
		This method prints the CBitVector in Hexadecimal format.
	*/
	void PrintHex(bool linebreak = true);

	/**
		This method prints the CBitVector in Hexadecimal format for the provided byte range.
		\param	fromByte		-		The byte from which the printing of CBitVector begins.
		\param	toByte			-		The byte until which the printing of CBitVector is done.
	*/
	void PrintHex(int fromByte, int toByte, bool linebreak = true);

	/**
		This method prints the CBitVector in Binary format. This method internally calls \link Print(int fromBit, int toBit) \endlink.
	*/
	void PrintBinary() {
		Print(0, m_nByteSize << 3);
	}

	/**
		This method is a more abstract printing method which is used to print the CBitVector even if the vector is a simple 1 bit based
		vector or 1-d array/vector or even a 2-d vector/array. This method internally calls methods \link Get(int i) \endlink and
		\link Get2D(int i, int j) \endlink.
	*/
	void PrintContent();

	/**
		This method prints the CBitVector bitwise for provided bit range with mask. This method internally calls \link  GetBit(int idx) \endlink.
		\param	fromBit			-		The bit from which the printing starts in a CBitVector.
		\param	toBit			-		The bit until which the printing in a CBitVector is done.
	*/
	void PrintBinaryMasked(int from, int to);

	/*
	 * If the cbitvector is abstracted to an array of elements with m_nElementLength bits size, these methods can be used for easier access
	 */

	/**
		Generic method which provides more abstraction for getting elements in the CBitVector. It is mainly used for getting values which are
		1-dimensional in nature. This method internally calls \link Get(int pos, int len) \endlink.
		\param	i		-		Index from which data needs to be fetched.
	*/
	template<class T> T Get(int i) {
		return Get<T>(i * m_nElementLength, m_nElementLength);
	}
	/**
		Generic method which provides more abstraction for setting elements in the CBitVector. It is mainly used for getting values which are
		1-dimensional in nature. This method internally calls \link Set(int pos, int len) \endlink.
		\param	val		-		Value which needs to be written to the given location.
		\param	i		-		Index to which data needs to be written to.
	*/
	template<class T> void Set(T val, int i) {
		Set<T>(val, i * m_nElementLength, m_nElementLength);
	}
	/*
	 * The same as the above methods only for two-dimensional access
	 */
	/**
		Generic method which provides more abstraction for getting elements in the CBitVector. It is mainly used for getting values which are
		2-dimensional in nature. This method internally calls \link Get(int pos, int len) \endlink.
		\param	i		-		Row index from which the data needs to be read.
		\param	j		-		Column index from which the data needs to be read.
	*/
	template<class T> T Get2D(int i, int j) {
		return Get<T>((i * m_nNumElementsDimB + j) * m_nElementLength, m_nElementLength);
	}

	/**
		Generic method which provides more abstraction for setting elements in the CBitVector. It is mainly used for getting values which are
		2-dimensional in nature. This method internally calls \link Set(int pos, int len) \endlink.
		\param	val		-		Value which needs to be written to the given location.
		\param	i		-		Row index from which the data needs to be written.
		\param	j		-		Column index from which the data needs to be written.
	*/
	template<class T> void Set2D(T val, int i, int j) {
		Set<T>(val, (i * m_nNumElementsDimB + j) * m_nElementLength, m_nElementLength);
	}
	//useful when accessing elements using an index

	//View the cbitvector as a rows x columns matrix and transpose
	void Transpose(int rows, int columns);
	void EklundhBitTranspose(int rows, int columns);
	void SimpleTranspose(int rows, int columns);

private:
	BYTE* m_pBits;	/** Byte pointer which stores the CBitVector as simple byte array. */
	uint64_t m_nByteSize; /** Byte size variable which stores the size of CBitVector in bytes. */
	uint64_t m_nBits; //The exact number of bits
	uint64_t m_nElementLength; /** Size of elements in the CBitVector. By default, it is set to 1. It is used
	 	 	 	 	 	 	 	   differently when it is used as 1-d or 2-d custom vector/array. */
	uint64_t m_nNumElements;  /** Number elements in the first dimension in the CBitVector. */
	uint64_t m_nNumElementsDimB;/** Number elements in the second dimension in the CBitVector. */
};

#endif /* BITVECTOR_H_ */
