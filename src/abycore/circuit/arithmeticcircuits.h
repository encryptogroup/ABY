/**
 \file		arithmeticcircuits.h
 \author	michael.zohner@ec-spride.de
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

 \brief		A collection of boolean circuits for boolean and yao sharing in the ABY framework
 */
#ifndef __ARITHMETICCIRCUITS_H_
#define __ARITHMETICCIRCUITS_H_

#include "../ENCRYPTO_utils/typedefs.h"
#include "abycircuit.h"
#include "circuit.h"

/** Arithmetic Circuit class.*/
class ArithmeticCircuit: public Circuit {
public:
	ArithmeticCircuit(ABYCircuit* aby, e_sharing context, e_role myrole, uint32_t bitlen) :
			Circuit(aby, context, myrole, bitlen, C_ARITHMETIC) {
		Init();
	}
	;
	~ArithmeticCircuit() {
		Cleanup();
	}
	;

	void Init();
	void Cleanup();
	void Reset();

	uint32_t PutMULGate(uint32_t left, uint32_t right);
	uint32_t PutMULCONSTGate(uint32_t left, uint32_t right);
	uint32_t PutADDGate(uint32_t left, uint32_t right);
	uint32_t PutSUBGate(uint32_t left, uint32_t right);

	uint32_t PutINGate(e_role src);
	template<class T> uint32_t PutINGate(T val, e_role role){
		uint32_t gateid = PutINGate(role);
		if (role == m_eMyRole) {
			GATE* gate = m_pGates + gateid;
			gate->gs.ishare.inval = (UGATE_T*) calloc(ceil_divide(1 * m_nShareBitLen, sizeof(UGATE_T) * 8), sizeof(UGATE_T));

			*gate->gs.ishare.inval = (UGATE_T) val;
			gate->instantiated = true;
		}
		return gateid;
	}

	uint32_t PutSIMDINGate(uint32_t nvals, e_role src);
	template<class T> uint32_t PutSIMDINGate(uint32_t nvals, T val, e_role role);

	//SharedIN
	uint32_t PutSharedINGate();
	template<class T> uint32_t PutSharedINGate(T val);
	uint32_t PutSharedSIMDINGate(uint32_t nvals);
	template<class T> uint32_t PutSharedSIMDINGate(uint32_t nvals, T val);

	share* PutDummyINGate(uint32_t bitlen);
	share* PutDummySIMDINGate(uint32_t nvals, uint32_t bitlen);


	template<class T> share* InternalPutINGate(uint32_t nvals, T val, uint32_t bitlen, e_role role);
	/* Unfortunately, a template function cannot be used due to virtual */
	share* PutINGate(uint64_t val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint64_t>(1, val, bitlen, role);
	}
	share* PutINGate(uint32_t val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint32_t>(1, val, bitlen, role);
	};
	share* PutINGate(uint16_t val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint16_t>(1, val, bitlen, role);
	};
	share* PutINGate(uint8_t val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint8_t>(1, val, bitlen, role);
	};

	share* PutSIMDINGate(uint32_t nvals, uint64_t val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint64_t>(nvals, val, bitlen, role);
	}
	share* PutSIMDINGate(uint32_t nvals, uint32_t val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint32_t>(nvals, val, bitlen, role);
	};
	share* PutSIMDINGate(uint32_t nvals, uint16_t val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint16_t>(nvals, val, bitlen, role);
	};
	share* PutSIMDINGate(uint32_t nvals, uint8_t val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint8_t>(nvals, val, bitlen, role);
	};



	template<class T> share* InternalPutINGate(uint32_t nvals, T* val, uint32_t bitlen, e_role role);
	/* Unfortunately, a template function cannot be used due to virtual. Call Internal PutINGate*/
	share* PutINGate(uint64_t* val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint64_t>(1, val, bitlen, role);
	};
	share* PutINGate(uint32_t* val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint32_t>(1, val, bitlen, role);
	};
	share* PutINGate(uint16_t* val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint16_t>(1, val, bitlen, role);
	};
	share* PutINGate(uint8_t* val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint8_t>(1, val, bitlen, role);
	};

	share* PutSIMDINGate(uint32_t nvals, uint64_t* val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint64_t>(nvals, val, bitlen, role);
	};
	share* PutSIMDINGate(uint32_t nvals, uint32_t* val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint32_t>(nvals, val, bitlen, role);
	};
	share* PutSIMDINGate(uint32_t nvals, uint16_t* val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint16_t>(nvals, val, bitlen, role);
	};
	share* PutSIMDINGate(uint32_t nvals, uint8_t* val, uint32_t bitlen, e_role role) {
		return InternalPutINGate<uint8_t>(nvals, val, bitlen, role);
	};

	template<class T> share* InternalPutSharedINGate(uint32_t nvals, T val, uint32_t bitlen);
	/* Unfortunately, a template function cannot be used due to virtual */
	share* PutSharedINGate(uint64_t val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint64_t>(1, val, bitlen);
	}
	share* PutSharedINGate(uint32_t val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint32_t>(1, val, bitlen);
	};
	share* PutSharedINGate(uint16_t val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint16_t>(1, val, bitlen);
	};
	share* PutSharedINGate(uint8_t val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint8_t>(1, val, bitlen);
	};

	share* PutSharedSIMDINGate(uint32_t nvals, uint64_t val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint64_t>(nvals, val, bitlen);
	}
	share* PutSharedSIMDINGate(uint32_t nvals, uint32_t val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint32_t>(nvals, val, bitlen);
	};
	share* PutSharedSIMDINGate(uint32_t nvals, uint16_t val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint16_t>(nvals, val, bitlen);
	};
	share* PutSharedSIMDINGate(uint32_t nvals, uint8_t val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint8_t>(nvals, val, bitlen);
	};


	//SharedIN
	template<class T> share* InternalPutSharedINGate(uint32_t nvals, T* val, uint32_t bitlen);
	/* Unfortunately, a template function cannot be used due to virtual. Call Internal PutSharedINGate*/
	share* PutSharedINGate(uint64_t* val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint64_t>(1, val, bitlen);
	};
	share* PutSharedINGate(uint32_t* val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint32_t>(1, val, bitlen);
	};
	share* PutSharedINGate(uint16_t* val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint16_t>(1, val, bitlen);
	};
	share* PutSharedINGate(uint8_t* val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint8_t>(1, val, bitlen);
	};

	share* PutSharedSIMDINGate(uint32_t nvals, uint64_t* val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint64_t>(nvals, val, bitlen);
	};
	share* PutSharedSIMDINGate(uint32_t nvals, uint32_t* val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint32_t>(nvals, val, bitlen);
	};
	share* PutSharedSIMDINGate(uint32_t nvals, uint16_t* val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint16_t>(nvals, val, bitlen);
	};
	share* PutSharedSIMDINGate(uint32_t nvals, uint8_t* val, uint32_t bitlen) {
		return InternalPutSharedINGate<uint8_t>(nvals, val, bitlen);
	};


	uint32_t PutOUTGate(uint32_t parent, e_role dst);
	share* PutOUTGate(share* parent, e_role dst);

        std::vector<uint32_t> PutSharedOUTGate(std::vector<uint32_t> parentids);
	share* PutSharedOUTGate(share* parent);


	share* PutCallbackGate(share* in, uint32_t rounds, void (*callback)(GATE*, void*), void* infos, uint32_t nvals);
	share* PutTruthTableGate(share* in, uint64_t* ttable);
	share* PutTruthTableMultiOutputGate(share* in, uint32_t out_bits, uint64_t* ttable);



	uint32_t PutINVGate(uint32_t parentid);
	uint32_t PutCONVGate(std::vector<uint32_t> parentids);

	share* PutADDGate(share* ina, share* inb);

	share* PutSUBGate(share* ina, share* inb);
	share* PutANDGate(share*, share*) {
                std::cerr << "AND not implemented in arithmetic sharing" << std::endl;
		return new arithshare(this);
	}
	share* PutXORGate(share*, share*) {
          std::cerr << "XOR not implemented in arithmetic sharing" << std::endl;
		return new arithshare(this);
	}
	share* PutSubGate(share*, share*) {
		std::cerr << "Sub not implemented in arithmetic sharing" << std::endl;
		return new arithshare(this);
	}
	share* PutMULGate(share* ina, share* inb);

	/* Multiplication with a constant - offline & free */
	share* PutMULCONSTGate(share* ina, share* inb);

	share* PutGTGate(share*, share*) {
		std::cerr << "GT not implemented in arithmetic sharing" << std::endl;
		return new arithshare(this);
	}
	share* PutEQGate(share*, share*) {
		std::cerr << "EQ not implemented in arithmetic sharing" << std::endl;
		return new arithshare(this);
	}
	share* PutMUXGate(share*, share*, share*) {
		std::cerr << "MUX not implemented in arithmetic sharing" << std::endl;
		return new arithshare(this);
	}
	share* PutY2BGate(share*) {
		std::cerr << "Y2B not implemented in arithmetic sharing" << std::endl;
		return new arithshare(this);
	}
	share* PutB2YGate(share*) {
		std::cerr << "B2Y not implemented in arithmetic sharing" << std::endl;
		return new arithshare(this);
	}
	share* PutA2YGate(share*) {
		std::cerr << "A2Y not implemented in arithmetic sharing" << std::endl;
		return new arithshare(this);
	}
	share* PutANDVecGate(share*, share*) {
          std::cerr << "ANDVec Gate not implemented in arithmetic sharing" << std::endl;
		return new arithshare(this);
	}
	uint32_t PutB2AGate(std::vector<uint32_t> ina);
	share* PutB2AGate(share* ina);


	uint32_t GetNumMULGates() {
		return m_nMULs;
	}
	;
	uint32_t GetNumCONVGates() {
		return m_nCONVGates;
	}
	;

	//share* PutCONSGate(UGATE_T val, uint32_t nvals = 1);
	share* PutCONSGate(UGATE_T val, uint32_t bitlen);
	share* PutCONSGate(uint8_t* val, uint32_t bitlen);
	share* PutCONSGate(uint32_t* val, uint32_t bitlen);

	share* PutSIMDCONSGate(uint32_t nvals, UGATE_T val, uint32_t bitlen);
	share* PutSIMDCONSGate(uint32_t nvals, uint8_t* val, uint32_t bitlen);
	share* PutSIMDCONSGate(uint32_t nvals, uint32_t* val, uint32_t bitlen);

	uint32_t PutConstantGate(UGATE_T val, uint32_t nvals = 1);
	uint32_t GetMaxCommunicationRounds() {
		return m_nMaxDepth;
	}
	;

private:
	void UpdateInteractiveQueue(uint32_t gateid);
	void UpdateLocalQueue(uint32_t gateid);

	uint32_t m_nMULs; //number of AND gates in the circuit
	uint32_t m_nCONVGates; //number of Boolean to arithmetic conversion gates
};

#endif /* __ARITHMETICCIRCUITS_H_ */
