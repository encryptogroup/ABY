#include <inttypes.h>

typedef enum conv_t{
	ENUM_UINT_TYPE, ENUM_FP_TYPE, ENUM_UNKNOWN_TYPE
}conv_t;

class ConvType{
public:
    virtual conv_t getType() = 0;
};

class FPType: public ConvType{
public:
	FPType(){};
	conv_t getType(){return ENUM_FP_TYPE;}
	virtual uint32_t getBase() = 0;
	virtual uint32_t getNumOfDigits() = 0;
	virtual uint32_t getExpBits() = 0;
	virtual uint32_t getExpBias() = 0;
};

class UINTType: public ConvType{
public:
	UINTType(){};
 	conv_t getType(){return ENUM_UINT_TYPE;}
	virtual uint32_t getNumOfDigits() = 0;
};

class FP32: public FPType{
public:
	uint32_t getBase(){return 2;}
	uint32_t getNumOfDigits(){return 24-1;}
 	uint32_t getExpBits(){return 8;}
	uint32_t getExpBias(){return 127;}
   	FP32(){};
};

class FP64: public FPType{
public:
	uint32_t getBase(){return 2;}
	uint32_t getNumOfDigits(){return 53-1;}
 	uint32_t getExpBits(){return 11;}
 	uint32_t getExpBias(){return 1023;}
  	FP64(){};
};

class UINT32: public UINTType{
public:
   	 uint32_t getNumOfDigits(){return 32;};
  	 UINT32(){};
};

class UINT64: public UINTType{
public:
	 uint32_t getNumOfDigits(){return 64;};
 	 UINT64(){};
};

