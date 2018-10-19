/**
 \file 		yaokey.h
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
 \brief		YaoKey Implementation
 */

#ifndef __YAOKEY_H_
#define __YAOKEY_H_

#include <ENCRYPTO_utils/typedefs.h>
/* an interface to operations on yaos garbled circuits keys for pre-defined symmetric security sizes */

#define _MSB_UINT64_T 0x80000000000000L
#define _TWO_MSB_UINT64_T 0xC0000000000000L
#define _TWO_MSB_DOWNSHIFT 62

class YaoKey {
public:
	virtual ~YaoKey() {
	}
	;
	virtual void XOR(BYTE* out, BYTE* ina, BYTE* inb) = 0;
	virtual void XOR_DOUBLE_B(BYTE* out, BYTE* ina, BYTE* inb) = 0;
	virtual void XOR_QUAD_B(BYTE* out, BYTE* ina, BYTE* inb) = 0;
};

class YaoKeyST: public YaoKey {
public:
	YaoKeyST() {
	}
	;
	~YaoKeyST() {
	}
	;
	void XOR(BYTE* out, BYTE* ina, BYTE* inb) {
		(((UINT64_T*) (out))[0] = ((UINT64_T*) (ina))[0] ^ ((UINT64_T*) (inb))[0]);
		(((UINT16_T*) (out))[4] = ((UINT16_T*) (ina))[4] ^ ((UINT16_T*) (inb))[4]);
	};
	void XOR_DOUBLE_B(BYTE* out, BYTE* ina, BYTE* inb) {

		(((UINT64_T*) (out))[0] = ((UINT64_T*) (ina))[0] ^ ((UINT64_T*) (inb))[0]<<1);
		((UINT16_T*) (out))[4] = ((UINT16_T*) (ina))[4] ^ ((((UINT16_T*) (inb))[4]<<1) ^ (!!(((UINT64_T*) (inb))[0] & _MSB_UINT64_T)));
	};
	void XOR_QUAD_B(BYTE* out, BYTE* ina, BYTE* inb) {

		(((UINT64_T*) (out))[0] = ((UINT64_T*) (ina))[0] ^ ((UINT64_T*) (inb))[0]<<2);
		((UINT16_T*) (out))[4] = ((UINT16_T*) (ina))[4] ^ ((((UINT16_T*) (inb))[4]<<2) ^ ((((UINT64_T*) (inb))[0] & _TWO_MSB_UINT64_T))>>_TWO_MSB_DOWNSHIFT);
	};

};

class YaoKeyMT: public YaoKey {
public:
	YaoKeyMT() {
	}
	;
	~YaoKeyMT() {
	}
	;
	void XOR(BYTE* out, BYTE* ina, BYTE* inb) {
		(((UINT64_T*) (out))[0] = ((UINT64_T*) (ina))[0] ^ ((UINT64_T*) (inb))[0]);
		(((UINT32_T*) (out))[3] = ((UINT32_T*) (ina))[3] ^ ((UINT32_T*) (inb))[3]);
	};
	void XOR_DOUBLE_B(BYTE* out, BYTE* ina, BYTE* inb) {
		(((UINT64_T*) (out))[0] = ((UINT64_T*) (ina))[0] ^ ((UINT64_T*) (inb))[0]<<1);
		(((UINT32_T*) (out))[3] = ((UINT32_T*) (ina))[3] ^ ((UINT32_T*) (inb))[3]<<1);
		(((UINT32_T*) (out))[3] = ((UINT32_T*) (ina))[3] ^ (((UINT32_T*) (inb))[3]<<1) ^ (!!(((UINT64_T*) (inb))[0] & _MSB_UINT64_T)));
	};
	void XOR_QUAD_B(BYTE* out, BYTE* ina, BYTE* inb) {
		(((UINT64_T*) (out))[0] = ((UINT64_T*) (ina))[0] ^ ((UINT64_T*) (inb))[0]<<2);
		//(((UINT32_T*) (out))[3] = ((UINT32_T*) (ina))[3] ^ ((UINT32_T*) (inb))[3]<<2);
		(((UINT32_T*) (out))[3] = ((UINT32_T*) (ina))[3] ^ (((UINT32_T*) (inb))[3]<<2) ^ ((((UINT64_T*) (inb))[0] & _TWO_MSB_UINT64_T))>>_TWO_MSB_DOWNSHIFT);
	};
};
class YaoKeyLT: public YaoKey {
public:

	~YaoKeyLT() {
	}
	;
	void XOR(BYTE* out, BYTE* ina, BYTE* inb) {
		(((UINT64_T*) (out))[0] = ((UINT64_T*) (ina))[0] ^ ((UINT64_T*) (inb))[0]);
		(((UINT64_T*) (out))[1] = ((UINT64_T*) (ina))[1] ^ ((UINT64_T*) (inb))[1]);
	};
	void XOR_DOUBLE_B(BYTE* out, BYTE* ina, BYTE* inb) {
		(((UINT64_T*) (out))[0] = ((UINT64_T*) (ina))[0] ^ ((UINT64_T*) (inb))[0]<<1);
		(((UINT64_T*) (out))[1] = ((UINT64_T*) (ina))[1] ^ (((UINT64_T*) (inb))[1]<<1) ^ (!!(((UINT64_T*) (inb))[0] & _MSB_UINT64_T)));
	};
	void XOR_QUAD_B(BYTE* out, BYTE* ina, BYTE* inb) {
		(((UINT64_T*) (out))[0] = ((UINT64_T*) (ina))[0] ^ ((UINT64_T*) (inb))[0]<<2);
		(((UINT64_T*) (out))[1] = ((UINT64_T*) (ina))[1] ^ (((UINT64_T*) (inb))[1]<<2) ^ ((((UINT64_T*) (inb))[0] & _TWO_MSB_UINT64_T))>>_TWO_MSB_DOWNSHIFT);
	};
};

class YaoKeyXLT: public YaoKey {
public:

	~YaoKeyXLT() {
	}
	;
	void XOR(BYTE* out, BYTE* ina, BYTE* inb) {
		(((UINT64_T*) (out))[0] = ((UINT64_T*) (ina))[0] ^ ((UINT64_T*) (inb))[0]);
		(((UINT64_T*) (out))[1] = ((UINT64_T*) (ina))[1] ^ ((UINT64_T*) (inb))[1]);
		(((UINT64_T*) (out))[2] = ((UINT64_T*) (ina))[2] ^ ((UINT64_T*) (inb))[2]);

	};
	void XOR_DOUBLE_B(BYTE* out, BYTE* ina, BYTE* inb) {
		(((UINT64_T*) (out))[0] = ((UINT64_T*) (ina))[0] ^ ((UINT64_T*) (inb))[0]<<1);
		(((UINT64_T*) (out))[1] = ((UINT64_T*) (ina))[1] ^ (((UINT64_T*) (inb))[1]<<1) ^ (!!(((UINT64_T*) (inb))[0] & _MSB_UINT64_T)));
		(((UINT64_T*) (out))[2] = ((UINT64_T*) (ina))[2] ^ (((UINT64_T*) (inb))[2]<<1) ^ (!!(((UINT64_T*) (inb))[1] & _MSB_UINT64_T)));

	};
	void XOR_QUAD_B(BYTE* out, BYTE* ina, BYTE* inb) {
		(((UINT64_T*) (out))[0] = ((UINT64_T*) (ina))[0] ^ ((UINT64_T*) (inb))[0]<<2);
		(((UINT64_T*) (out))[1] = ((UINT64_T*) (ina))[1] ^ (((UINT64_T*) (inb))[1]<<2) ^ ((((UINT64_T*) (inb))[0] & _TWO_MSB_UINT64_T))>>_TWO_MSB_DOWNSHIFT);
		(((UINT64_T*) (out))[2] = ((UINT64_T*) (ina))[2] ^ (((UINT64_T*) (inb))[2]<<2) ^ ((((UINT64_T*) (inb))[1] & _TWO_MSB_UINT64_T))>>_TWO_MSB_DOWNSHIFT);
	};
};

class YaoKeyXXLT: public YaoKey {
public:

	~YaoKeyXXLT() {
	}
	;
	void XOR(BYTE* out, BYTE* ina, BYTE* inb) {
		(((UINT64_T*) (out))[0] = ((UINT64_T*) (ina))[0] ^ ((UINT64_T*) (inb))[0]);
		(((UINT64_T*) (out))[1] = ((UINT64_T*) (ina))[1] ^ ((UINT64_T*) (inb))[1]);
		(((UINT64_T*) (out))[2] = ((UINT64_T*) (ina))[2] ^ ((UINT64_T*) (inb))[2]);
		(((UINT64_T*) (out))[3] = ((UINT64_T*) (ina))[3] ^ ((UINT64_T*) (inb))[3]);
	};
	void XOR_DOUBLE_B(BYTE* out, BYTE* ina, BYTE* inb) {
		(((UINT64_T*) (out))[0] = ((UINT64_T*) (ina))[0] ^ ((UINT64_T*) (inb))[0]<<1);
		(((UINT64_T*) (out))[1] = ((UINT64_T*) (ina))[1] ^ (((UINT64_T*) (inb))[1]<<1) ^ (!!(((UINT64_T*) (inb))[0] & _MSB_UINT64_T)));
		(((UINT64_T*) (out))[2] = ((UINT64_T*) (ina))[2] ^ (((UINT64_T*) (inb))[2]<<1) ^ (!!(((UINT64_T*) (inb))[1] & _MSB_UINT64_T)));
		(((UINT64_T*) (out))[3] = ((UINT64_T*) (ina))[3] ^ (((UINT64_T*) (inb))[3]<<1) ^ (!!(((UINT64_T*) (inb))[2] & _MSB_UINT64_T)));
	};
	void XOR_QUAD_B(BYTE* out, BYTE* ina, BYTE* inb) {
		(((UINT64_T*) (out))[0] = ((UINT64_T*) (ina))[0] ^ ((UINT64_T*) (inb))[0]<<2);
		(((UINT64_T*) (out))[1] = ((UINT64_T*) (ina))[1] ^ (((UINT64_T*) (inb))[1]<<2) ^ ((((UINT64_T*) (inb))[0] & _TWO_MSB_UINT64_T))>>_TWO_MSB_DOWNSHIFT);
		(((UINT64_T*) (out))[2] = ((UINT64_T*) (ina))[2] ^ (((UINT64_T*) (inb))[2]<<2) ^ ((((UINT64_T*) (inb))[1] & _TWO_MSB_UINT64_T))>>_TWO_MSB_DOWNSHIFT);
		(((UINT64_T*) (out))[3] = ((UINT64_T*) (ina))[3] ^ (((UINT64_T*) (inb))[3]<<2) ^ ((((UINT64_T*) (inb))[2] & _TWO_MSB_UINT64_T))>>_TWO_MSB_DOWNSHIFT);
	};
};

static void InitYaoKey(YaoKey** key, int symbits) {
	if (symbits == ST.symbits)
		*key = new YaoKeyST();
	else if (symbits == MT.symbits)
		*key = new YaoKeyMT();
	else if (symbits == LT.symbits)
		*key = new YaoKeyLT();
	else if (symbits == XLT.symbits)
		*key = new YaoKeyXLT();
	else if (symbits == XXLT.symbits)
		*key = new YaoKeyXXLT();
	else
		*key = new YaoKeyLT();
	return;
}

#endif /* __YAOKEY_H_ */
