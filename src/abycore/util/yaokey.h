/**
 \file 		yaokey.h
 \author 	michael.zohner@ec-spride.de
 \copyright __________________
 \brief		YaoKey Implementation
 */

#ifndef __YAOKEY_H_
#define __YAOKEY_H_

#include "typedefs.h"
/* an interface to operations on yaos garbled circuits keys for pre-defined symmetric security sizes */

#define _MSB_UINT64_T 0x80000000000000L

class YaoKey {
public:
	virtual ~YaoKey() {
	}
	;
	virtual void XOR(BYTE* out, BYTE* ina, BYTE* inb) = 0;
	virtual void XOR_DOUBLE_B(BYTE* out, BYTE* ina, BYTE* inb) = 0;
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
