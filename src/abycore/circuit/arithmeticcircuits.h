/**
 \file		arithmeticcircuits.h
 \author	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2019 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.

 \brief		A collection of boolean circuits for boolean and yao sharing in the ABY framework
 */
#ifndef __ARITHMETICCIRCUITS_H_
#define __ARITHMETICCIRCUITS_H_

#include <ENCRYPTO_utils/typedefs.h>
#include "abycircuit.h"
#include "circuit.h"
#include "share.h"
#include <cstring>

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
			GATE* gate = &(m_vGates[gateid]);
			gate->gs.ishare.inval = (UGATE_T*) calloc(ceil_divide(1 * m_nShareBitLen, sizeof(UGATE_T) * 8), sizeof(UGATE_T));

			*gate->gs.ishare.inval = (UGATE_T) val;
			gate->instantiated = true;
		}
		return gateid;
	}

	uint32_t PutSIMDINGate(uint32_t nvals, e_role src);

	template<class T> uint32_t PutSIMDINGate(uint32_t nvals, T val, e_role role) {
		uint32_t gateid = PutSIMDINGate(nvals, role);
		if (role == m_eMyRole) {
			GATE* gate = &(m_vGates[gateid]);
			gate->gs.ishare.inval = (UGATE_T*) calloc(ceil_divide(nvals * m_nShareBitLen, GATE_T_BITS), sizeof(UGATE_T));

			*gate->gs.ishare.inval = (UGATE_T) val;
			gate->instantiated = true;
		}

		return gateid;
	}

	//SharedIN
	uint32_t PutSharedINGate();

	template<class T> uint32_t PutSharedINGate(T val) {
		uint32_t gateid = PutSharedINGate();
		GATE* gate = &(m_vGates[gateid]);
		gate->gs.val = (UGATE_T*) calloc(ceil_divide(1 * m_nShareBitLen, GATE_T_BITS), sizeof(UGATE_T));

		*gate->gs.val = (UGATE_T) val;
		gate->instantiated = true;
		return gateid;
	}

	uint32_t PutSharedSIMDINGate(uint32_t nvals);

	template<class T> uint32_t PutSharedSIMDINGate(uint32_t nvals, T val) {
		uint32_t gateid = PutSharedSIMDINGate(nvals);
		GATE* gate = &(m_vGates[gateid]);
		gate->gs.val = (UGATE_T*) calloc(ceil_divide(nvals * m_nShareBitLen, GATE_T_BITS), sizeof(UGATE_T));

		*gate->gs.val = (UGATE_T) val;
		gate->instantiated = true;
		return gateid;
	}

	share* PutDummyINGate(uint32_t bitlen);
	share* PutDummySIMDINGate(uint32_t nvals, uint32_t bitlen);


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

	share* PutTruthTableGate(share*, uint64_t*) {
		std::cerr << "PutTruthTableGate not implemented in ArithmeticCircuit!!" << std::endl;
		return NULL;
	}

	share* PutTruthTableMultiOutputGate(share*, uint32_t, uint64_t*) {
		std::cerr << "PutTruthTableMultiOutputGate not implemented in ArithmeticCircuit!!" << std::endl;
		return NULL;
	}



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
	share** PutCondSwapGate(share*, share*, share*, BOOL) {
		share** s_out = (share**) malloc(sizeof(share*) *2);
		s_out[0] = new arithshare(this);
		s_out[1] = new arithshare(this);
		std::cerr << "X not implemented in arithmetic sharing" << std::endl;
		return s_out;
	}
	share* PutUniversalGate(share*, share*, uint32_t) {
		std::cerr << "UNIV not implemented in arithmetic sharing" << std::endl;
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

	//SharedIN
	template<class T> share* InternalPutSharedINGate(uint32_t nvals, T* val, uint32_t bitlen) {
		assert(bitlen <= m_nShareBitLen);
		share* shr = new arithshare(this);
		uint32_t gateid = PutSharedSIMDINGate(nvals);
		assert((sizeof(UGATE_T) / sizeof(T)) > 0);
		shr->set_wire_id(0, gateid);

		GATE* gate = &(m_vGates[gateid]);
		uint32_t sharebytelen = ceil_divide(m_nShareBitLen, 8);
		uint32_t inbytelen = ceil_divide(bitlen, 8);
		gate->gs.val = (UGATE_T*) calloc(nvals, PadToMultiple(sharebytelen, sizeof(UGATE_T)));
		for (uint32_t i = 0; i < nvals; i++) {
			memcpy(((uint8_t*) gate->gs.val) + i * sharebytelen, val + i, inbytelen);
		}
		gate->instantiated = true;
		return shr;
	}

	template<class T> share* InternalPutSharedINGate(uint32_t nvals, T val, [[maybe_unused]] uint32_t bitlen) {
		share* shr = new arithshare(this);
		shr->set_wire_id(0, PutSharedSIMDINGate(nvals, val));
		return shr;
	}

	template<class T> share* InternalPutINGate(uint32_t nvals, T* val, uint32_t bitlen, e_role role) {
		assert(bitlen <= m_nShareBitLen);
		share* shr = new arithshare(this);
		uint32_t gateid = PutSIMDINGate(nvals, role);
		assert((sizeof(UGATE_T) / sizeof(T)) > 0);
		shr->set_wire_id(0, gateid);

		if (role == m_eMyRole) {
			GATE* gate = &(m_vGates[gateid]);
			uint32_t sharebytelen = ceil_divide(m_nShareBitLen, 8);
			uint32_t inbytelen = ceil_divide(bitlen, 8);
			gate->gs.ishare.inval = (UGATE_T*) calloc(nvals, PadToMultiple(sharebytelen, sizeof(UGATE_T)));
			for (uint32_t i = 0; i < nvals; i++) {
				memcpy(((uint8_t*) gate->gs.ishare.inval) + i * sharebytelen, val + i, inbytelen);
			}

			gate->instantiated = true;
		}

		return shr;
	}

	template<class T> share* InternalPutINGate(uint32_t nvals, T val, [[maybe_unused]] uint32_t bitlen, e_role role) {
		share* shr = new arithshare(this);
		shr->set_wire_id(0, PutSIMDINGate(nvals, val, role));
		return shr;
	}

};

#endif /* __ARITHMETICCIRCUITS_H_ */
