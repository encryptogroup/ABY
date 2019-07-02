/**
 \file		arithsharing.cpp
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
 \brief		Arithmetic Sharing class implementation
 */

#include <algorithm>
#include "arithsharing.h"
#include "../aby/abysetup.h"

template<typename T>
void ArithSharing<T>::Init() {
	m_nMTs = 0;

	m_nTypeBitLen = sizeof(T) * 8;

	memset(&m_nTypeBitMask, 0, sizeof(uint64_t));
	memset(&m_nTypeBitMask, 0xFF, sizeof(T));

	m_cArithCircuit = new ArithmeticCircuit(m_pCircuit, m_eContext, m_eRole, m_nTypeBitLen);

	m_nConvShareIdx = 0;
	m_nConvShareIdx2 = 0;
	m_nConvShareSndCtr = 0;
	m_nConvShareRcvCtr = 0;

	m_nInputShareSndCtr = 0;
	m_nOutputShareSndCtr = 0;
	m_nInputShareRcvCtr = 0;
	m_nOutputShareRcvCtr = 0;

	m_vCONVGates.clear();
	m_vCONVGates2.clear();
}

//Pre-set values for new layer
template<typename T>
void ArithSharing<T>::InitNewLayer() {
	//Create new random values for this layer
	if (m_nInputShareSndCtr > 0) {
		//TODO: exchange by input and output variables
		uint32_t invals = m_cArithCircuit->GetNumInputBitsForParty(m_eRole);
		m_vInputShareSndBuf.Create((uint64_t) invals * m_nTypeBitLen, m_cCrypto);

#ifdef DEBUGARITH
		std::cout << " m_vInputShareSndBuf at init new layer = ";
		m_vInputShareSndBuf.PrintHex();
#endif
	}

	m_nInputShareRcvCtr = 0;
	m_nOutputShareRcvCtr = 0;

	m_nInputShareSndCtr = 0;
	m_nOutputShareSndCtr = 0;

	m_vMULGates.clear();
	m_vInputShareGates.clear();
	m_vOutputShareGates.clear();

}

template<typename T>
void ArithSharing<T>::PrepareSetupPhase(ABYSetup* setup) {
	m_nMTs = m_cArithCircuit->GetNumMULGates();

	InitMTs();

	if (m_nMTs > 0) {
		if (m_eMTGenAlg == MT_PAILLIER || m_eMTGenAlg == MT_DGK) {
			PKMTGenVals* pgentask = (PKMTGenVals*) malloc(sizeof(PKMTGenVals));
			pgentask->A = &(m_vA[0]);
			pgentask->B = &(m_vB[0]);
			pgentask->C = &(m_vC[0]);
			pgentask->numMTs = m_nMTs;
			pgentask->sharebitlen = m_nTypeBitLen;
			setup->AddPKMTGenTask(pgentask);
		} else {
			for (uint32_t i = 0; i < 2; i++) {
				ArithMTMasking<T> *fMaskFct = new ArithMTMasking<T>(1, &(m_vB[0])); //TODO to implement the vector multiplication change first argument
				IKNP_OTTask* task = (IKNP_OTTask*) malloc(sizeof(IKNP_OTTask));
				task->bitlen = m_nTypeBitLen;
				task->snd_flavor = Snd_C_OT;
				task->rec_flavor = Rec_OT;
				task->numOTs = m_nMTs * m_nTypeBitLen;
				task->mskfct = fMaskFct;
				task->delete_mskfct = TRUE;
				if ((m_eRole ^ i) == SERVER) {
					task->pval.sndval.X0 = &(m_vC[0]);
					task->pval.sndval.X1 = &(m_vC[0]);
				} else {
					task->pval.rcvval.C = &(m_vA[0]);
					task->pval.rcvval.R = &(m_vS[0]);
				}
#ifndef BATCH
				std::cout << "Adding a OT task which is supposed to perform " << task->numOTs << " OTs on " << m_nTypeBitLen << " bits for ArithMul" << std::endl;
#endif
				setup->AddOTTask(task, i);
			}
		}
	}

	m_nNumCONVs = m_cArithCircuit->GetNumCONVGates();
	if (m_nNumCONVs > 0) {
		XORMasking* fXORMaskFct = new XORMasking(m_nTypeBitLen); //TODO to implement the vector multiplication change first argument

		IKNP_OTTask* task = (IKNP_OTTask*) malloc(sizeof(IKNP_OTTask));
		task->bitlen = m_nTypeBitLen;
		task->snd_flavor = Snd_R_OT;
		task->rec_flavor = Rec_OT;
		task->numOTs = m_nNumCONVs;
		task->mskfct = fXORMaskFct;
		task->delete_mskfct = TRUE;
		if ((m_eRole) == SERVER) {
			m_vConversionMasks[0].Create(m_nNumCONVs, m_nTypeBitLen);
			m_vConversionMasks[1].Create(m_nNumCONVs, m_nTypeBitLen);
			task->pval.sndval.X0 = &(m_vConversionMasks[0]);
			task->pval.sndval.X1 = &(m_vConversionMasks[1]);
		} else {
			m_vConversionMasks[0].Create(m_nNumCONVs, m_cCrypto); //the choice bits of the receiver
			m_vConversionMasks[1].Create(m_nNumCONVs, m_nTypeBitLen); //the resulting masks
			task->pval.rcvval.C = &(m_vConversionMasks[0]);
			task->pval.rcvval.R = &(m_vConversionMasks[1]);
		}
#ifdef DEBUGARITH
		std::cout << "Conv: Adding an OT task to perform " << task->numOTs <<
				" OTs for B2A" << std::endl;
#endif
		setup->AddOTTask(task, 0);

		// Pre-create some conversion buffers
		// TODO Network send buffers could be much smaller, only used per round.
		// But since there's currently no way of knowing in advance each round's
		// conversion gates, the send buffer is created with max possible size...
		if (m_eRole == CLIENT) {
			m_vConvShareSndBuf.Create(m_nNumCONVs, 1);
		} else {
			m_vConvShareSndBuf.Create(2 * m_nNumCONVs, m_nTypeBitLen);
		}
		// Note: Network receive buffer m_vConvShareRcvBuf is created per round in
		// GetBuffersToReceive
		m_vConversionRandomness.Create(m_nNumCONVs, m_nTypeBitLen, m_cCrypto);
	}
}

template<typename T>
void ArithSharing<T>::PerformSetupPhase([[maybe_unused]] ABYSetup* setup) {
	//Do nothing
}

template<typename T>
void ArithSharing<T>::FinishSetupPhase([[maybe_unused]] ABYSetup* setup) {
#ifdef DEBUGARITH
	for(uint32_t i = 0; i < m_nMTs; i++) {
		std::cout << "Output from OT: A: " << (uint64_t) m_vA[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen) << ", B: " << (uint64_t) m_vB[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen)
		<< ", C: " << (uint64_t) m_vC[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen) << ", S: " << (uint64_t) m_vS[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen) << std::endl;
	}
#endif
	if (m_eMTGenAlg == MT_OT) {
		//Compute Multiplication Triples
		ComputeMTsFromOTs();
	}

	FinishMTGeneration();
#ifdef VERIFY_ARITH_MT
	VerifyArithMT(setup);
#endif

#ifdef DEBUGARITH
	std::cout << " m_vInputShareSndBuf at end of setup phase = ";
	m_vInputShareSndBuf.PrintHex();
#endif
}

template<typename T>
void ArithSharing<T>::InitMTs() {
	m_vMTIdx.resize(1, 0);
	m_vMTStartIdx.resize(1, 0);
	m_vA.resize(1);
	m_vC.resize(1);
	m_vB.resize(1);
	m_vS.resize(1);

	m_vA[0].Create(m_nMTs, m_nTypeBitLen, m_cCrypto);
	m_vB[0].Create(m_nMTs, m_nTypeBitLen, m_cCrypto);
	m_vC[0].Create(m_nMTs, m_nTypeBitLen);
	m_vS[0].Create(m_nMTs, m_nTypeBitLen);

	m_vD_snd.resize(1);
	m_vE_snd.resize(1);
	m_vD_rcv.resize(1);
	m_vE_rcv.resize(1);

	m_vResA.resize(1);
	m_vResB.resize(1);
}

template<typename T>
void ArithSharing<T>::ComputeMTsFromOTs() {
	CBitVector temp(m_nMTs);

	T tmp;
	for (uint32_t i = 0; i < m_nMTs; i++) {
		tmp = m_vA[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen)
				* m_vB[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen);
		tmp += m_vC[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen);
		tmp += m_vS[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen);
		m_vC[0].template Set<T>(tmp, i * m_nTypeBitLen, m_nTypeBitLen);
#ifdef DEBUGARITH
		std::cout << "Computed MT " << i << ": ";
		std::cout << "A: " << (uint64_t) m_vA[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen) << ", B: " << (uint64_t) m_vB[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen)
		<< ", C: " << (uint64_t) m_vC[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen) << std::endl;
#endif

	}
}

template<typename T>
void ArithSharing<T>::FinishMTGeneration() {
	uint32_t bytesMTs = ceil_divide(m_nMTs * m_nTypeBitLen, 8);

	//Pre-store the values in A and B in D_snd and E_snd
	m_vD_snd[0].Create(m_nMTs, m_nTypeBitLen);
	m_vE_snd[0].Create(m_nMTs, m_nTypeBitLen);
	m_vD_snd[0].Copy(m_vA[0].GetArr(), 0, bytesMTs);
	m_vE_snd[0].Copy(m_vB[0].GetArr(), 0, bytesMTs);

	m_vD_rcv[0].Create(m_nMTs, m_nTypeBitLen);
	m_vE_rcv[0].Create(m_nMTs, m_nTypeBitLen);

	m_vResA[0].Create(m_nMTs, m_nTypeBitLen);
	m_vResB[0].Create(m_nMTs, m_nTypeBitLen);
}

template<typename T>
void ArithSharing<T>::PrepareOnlinePhase() {
	uint32_t myinvals = m_cArithCircuit->GetNumInputBitsForParty(m_eRole);
	uint32_t myoutvals = m_cArithCircuit->GetNumOutputBitsForParty(m_eRole);

	uint32_t otherinvals = m_cArithCircuit->GetNumInputBitsForParty(m_eRole == SERVER ? CLIENT : SERVER);
	uint32_t otheroutvals = m_cArithCircuit->GetNumOutputBitsForParty(m_eRole == SERVER ? CLIENT : SERVER);

#ifndef BATCH
	std::cout << "ninputvals = " << myinvals << ", noutputvals = " << myoutvals << ", typelen = " << m_nTypeBitLen << std::endl;
#endif

	m_vInputShareSndBuf.Create(myinvals, m_nTypeBitLen, m_cCrypto);
#ifdef DEBUGARITH
	std::cout << " m_vInputShareSndBuf at prep online phase = ";
	m_vInputShareSndBuf.PrintHex();
#endif

	m_vOutputShareSndBuf.Create(otheroutvals, m_nTypeBitLen);

	m_vInputShareRcvBuf.Create(otherinvals, m_nTypeBitLen);
	m_vOutputShareRcvBuf.Create(myoutvals, m_nTypeBitLen);

	InitNewLayer();
}

template<typename T>
void ArithSharing<T>::EvaluateLocalOperations(uint32_t depth) {
	std::deque<uint32_t> localops = m_cArithCircuit->GetLocalQueueOnLvl(depth);

	for (uint32_t i = 0; i < localops.size(); i++) {
		GATE* gate = &(m_vGates[localops[i]]);

#ifdef DEBUGARITH
		std::cout << "Evaluating gate with id = " << localops[i] << " of type " << gate->type << std::endl;
#endif

		if (IsSIMDGate(gate->type)) {
			EvaluateSIMDGate(localops[i]);
		} else if (gate->type == G_LIN) {
#ifdef DEBUGARITH
			std::cout << " which is an ADD gate" << std::endl;
#endif
			EvaluateADDGate(gate);
		} else if (gate->type == G_INV) {
#ifdef DEBUGARITH
			std::cout << " which is an INV gate" << std::endl;
#endif
			EvaluateINVGate(gate);
		} else if (gate->type == G_NON_LIN_CONST) {
#ifdef DEBUGARITH
			std::cout << " which is a MULCONST gate" << std::endl;
#endif
			EvaluateMULCONSTGate(gate);
		} else if (gate->type == G_CONSTANT) {
			EvaluateConstantGate(gate);
		} else if (gate->type == G_CALLBACK) {
			EvaluateCallbackGate(localops[i]);
		} else if (gate->type == G_SHARED_IN) {
			// nothing to do here
		} else if (gate->type == G_SHARED_OUT) {
			GATE* parent = &(m_vGates[gate->ingates.inputs.parent]);
			InstantiateGate(gate);
			memcpy(gate->gs.val, parent->gs.val, gate->nvals * sizeof(T));
			UsedGate(gate->ingates.inputs.parent);
		} else if (gate->type == G_PRINT_VAL) {
			EvaluatePrintValGate(localops[i], C_ARITHMETIC);
		} else if (gate->type == G_ASSERT) {
			EvaluateAssertGate(localops[i], C_ARITHMETIC);
		} else {
			std::cerr << "Operation not recognized: " << (uint32_t) gate->type << "(" << get_gate_type_name(gate->type) << ")" << std::endl;
		}
	}
}

template<typename T>
void ArithSharing<T>::EvaluateInteractiveOperations(uint32_t depth) {

	std::deque<uint32_t> interactiveops = m_cArithCircuit->GetInteractiveQueueOnLvl(depth);

	for (uint32_t i = 0; i < interactiveops.size(); i++) {
		GATE* gate = &(m_vGates[interactiveops[i]]);

		if (gate->type == G_NON_LIN) {
#ifdef DEBUGARITH
			std::cout << " which is an MUL gate" << std::endl;
#endif
			SelectiveOpen(gate);
		} else if (gate->type == G_IN) {
			if (gate->gs.ishare.src == m_eRole) {
#ifdef DEBUGARITH
				std::cout << " which is my input gate" << std::endl;
#endif
				ShareValues(gate);
			} else {
#ifdef DEBUGARITH
				std::cout << " which is the other parties input gate" << std::endl;
#endif
				m_vInputShareGates.push_back(gate);
				m_nInputShareRcvCtr += gate->nvals;
			}
		} else if (gate->type == G_OUT) {
			if (gate->gs.oshare.dst == m_eRole) {
#ifdef DEBUGARITH
				std::cout << " which is my output gate" << std::endl;
#endif
				m_vOutputShareGates.push_back(gate);
				m_nOutputShareRcvCtr += gate->nvals;
			} else if (gate->gs.oshare.dst == ALL) {
#ifdef DEBUGARITH
				std::cout << " which is an output gate for both of us" << std::endl;
#endif
				ReconstructValue(gate);
				m_vOutputShareGates.push_back(gate);
				m_nOutputShareRcvCtr += gate->nvals;
			} else {
#ifdef DEBUGARITH
				std::cout << " which is the other parties output gate" << std::endl;
#endif
				ReconstructValue(gate);
			}
		} else if (gate->type == G_CONV) {
#ifdef DEBUGARITH
			std::cout << " which is a conversion gate" << std::endl;
#endif
			EvaluateCONVGate(gate);
		} else if (gate->type == G_CALLBACK) {
			EvaluateCallbackGate(interactiveops[i]);
		} else {
			std::cerr << "Operation not recognized: " << (uint32_t) gate->type << "(" << get_gate_type_name(gate->type) << ")" << std::endl;
		}
	}
}

template<typename T>
void ArithSharing<T>::EvaluateConstantGate(GATE* gate) {
	UGATE_T value = gate->gs.constval;
	InstantiateGate(gate); // overwrites gs.constval by calloc of gs.aval
	gate->gs.constant.constval = value; // backup constant behind gs.aval
	if (m_eRole == CLIENT) value = 0;

	T* aval = reinterpret_cast<T*>(gate->gs.aval);
	for (uint32_t i = 0; i < gate->nvals; i++) {
		aval[i] = (T) value;
	}
}

template<typename T>
void ArithSharing<T>::EvaluateADDGate(GATE* gate) {
	uint32_t nvals = gate->nvals;
	uint32_t idleft = gate->ingates.inputs.twin.left;
	uint32_t idright = gate->ingates.inputs.twin.right;
	InstantiateGate(gate);

	for (uint32_t i = 0; i < nvals; i++) {
		((T*) gate->gs.aval)[i] = ((T*) m_vGates[idleft].gs.aval)[i] + ((T*) m_vGates[idright].gs.aval)[i];
#ifdef DEBUGARITH
		std::cout << "Result ADD (" << i << "): "<< ((T*)gate->gs.aval)[i] << " = " << ((T*) m_vGates[idleft].gs.aval)[i] << " + " << ((T*)m_vGates[idright].gs.aval)[i] << std::endl;
#endif
	}

	UsedGate(idleft);
	UsedGate(idright);
}

template<typename T>
void ArithSharing<T>::EvaluateMULCONSTGate(GATE* gate) {
	const uint32_t nvals = gate->nvals;
	const uint32_t idleft = gate->ingates.inputs.twin.left;
	const uint32_t idright = gate->ingates.inputs.twin.right;
	InstantiateGate(gate);
	// Find first constant. Doesn't matter if 2nd is also a constant, which would be
	// a weird circuit anyways...
	GATE* gate_const = &(m_vGates[idleft]);
	GATE* gate_var = &(m_vGates[idright]);
	if (!(gate_const->type == G_CONSTANT)) std::swap(gate_const, gate_var);
	assert (gate_const->type == G_CONSTANT && "At least one of the inputs in a MULCONST gate must be a constant.");
	// Current implementation of evaluation of CONST gates writes 0s to gs.aval
	// array on CLIENT side, so we need to take constant from constant struct
	const T constval = static_cast<T>(gate_const->gs.constant.constval);
	for (uint32_t i = 0; i < nvals; ++i) {
		((T*) gate->gs.aval)[i] = ((T*) gate_var->gs.aval)[i] * constval;
#ifdef DEBUGARITH
		std::cout << "Result MULCONST (" << i << "): "<< ((T*)gate->gs.aval)[i] << " = " << ((T*) gate_var->gs.aval)[i] << " * " << constval << std::endl;
#endif
	}

	UsedGate(idleft);
	UsedGate(idright);
}

template<typename T>
void ArithSharing<T>::ShareValues(GATE* gate) {
	T* input = (T*) gate->gs.ishare.inval;
	T tmpval;

#ifdef DEBUGARITH
	std::cout << " m_vInputShareSndBuf before inst gate = ";
	m_vInputShareSndBuf.PrintHex();
#endif

	InstantiateGate(gate);

	for (uint32_t i = 0; i < gate->nvals; i++, m_nInputShareSndCtr++) {
		tmpval = m_vInputShareSndBuf.template Get<T>(m_nInputShareSndCtr);
		((T*) gate->gs.aval)[i] = MOD_SUB(input[i], tmpval, m_nTypeBitMask);
#ifdef DEBUGARITH
		std::cout << "Shared: " << (uint64_t) ((T*)gate->gs.aval)[i] << " = " << (uint64_t) input[i] << " - " <<
		(uint64_t) m_vInputShareSndBuf.template Get<T>(m_nInputShareSndCtr) << ", " << m_nTypeBitMask <<
		", inputid on this layer = " << m_nInputShareSndCtr << ", tmpval = " << tmpval << std::endl;
		m_vInputShareSndBuf.PrintHex();
#endif
	}
	free(input);
}

template<typename T>
void ArithSharing<T>::EvaluateCONVGate(GATE* gate) {
	uint32_t* parentids = gate->ingates.inputs.parents; //gate->gs.parentgate;
	uint32_t nparents = gate->ingates.ningates;
	uint32_t nvals = gate->nvals;

#ifdef DEBUGARITH
	std::cout << "Values of B2A gates with id " << ((((uint64_t) gate)-((uint64_t)m_vGates.data()))/sizeof(GATE)) << ": ";
#endif
	for (uint32_t i = 0; i < nparents; i++) {
		if (m_vGates[parentids[i]].context == S_YAO)
			std::cerr << "can't convert from yao representation directly into arithmetic" << std::endl;
#ifdef DEBUGARITH
		std::cout << (uint32_t) m_vGates[parentids[i]].gs.val[0];
#endif

	}
#ifdef DEBUGARITH
	std::cout << std::endl;
	std::cout << "Evaluating conv gate which has " << nvals << " values, current number of conv gates: " << m_vCONVGates.size() << std::endl;
#endif

	m_vCONVGates.push_back(gate);
	if (m_eRole == SERVER) {
		m_nConvShareRcvCtr += nvals * nparents;
	} else {
		//Client routine - send bits
		//copy values into snd buffer
		m_vConvShareSndBuf.SetBitsPosOffset(m_vConversionMasks[0].GetArr(),
				m_nConvShareIdx + m_nConvShareSndCtr,
				m_nConvShareSndCtr, nparents * nvals);
		for (uint32_t i = 0; i < nparents; ++i) {
			//XOR the choice bits and the current values of the gate and write into the snd buffer
			m_vConvShareSndBuf.XORBits((BYTE*) m_vGates[parentids[i]].gs.val,
					m_nConvShareSndCtr, nvals);
			m_nConvShareSndCtr += nvals;
		}
#ifdef DEBUGARITH
		std::cout << "Conversion shares: ";
		m_vConvShareSndBuf.PrintBinary();
#endif
	}
}

template<typename T>
void ArithSharing<T>::ReconstructValue(GATE* gate) {
	uint32_t parentid = gate->ingates.inputs.parent;

	for (uint32_t i = 0; i < gate->nvals; i++, m_nOutputShareSndCtr++) {
		m_vOutputShareSndBuf.template Set<T>(((T*) m_vGates[parentid].gs.aval)[i], m_nOutputShareSndCtr);
#ifdef DEBUGARITH
		std::cout << "Sending output share: " << (uint64_t) ((T*)m_vGates[parentid].gs.aval)[i] << std::endl;
#endif
	}
	if (gate->gs.oshare.dst != ALL)
		UsedGate(parentid);
}

template<typename T>
void ArithSharing<T>::SelectiveOpen(GATE* gate) {
	uint32_t idleft = gate->ingates.inputs.twin.left;
	uint32_t idright = gate->ingates.inputs.twin.right;

	T d, e, x, y, a, b;
	for (uint32_t i = 0; i < gate->nvals; i++, m_vMTIdx[0]++) {
		a = m_vD_snd[0].template Get<T>(m_vMTIdx[0]);
		x = ((T*) m_vGates[idleft].gs.aval)[i];
		d = MOD_SUB(x, a, m_nTypeBitMask); //a > x ? m_nTypeBitMask - (a - 1) + x : x - a;
		m_vD_snd[0].template Set<T>(d, m_vMTIdx[0]);
		b = m_vE_snd[0].template Get<T>(m_vMTIdx[0]);
		y = ((T*) m_vGates[idright].gs.aval)[i];
		e = MOD_SUB(y, b, m_nTypeBitMask); //b > y ? m_nTypeBitMask - (b - 1) + y : y - b;
		m_vE_snd[0].template Set<T>(e, m_vMTIdx[0]);
	}
	m_vMULGates.push_back(gate);

	UsedGate(idleft);
	UsedGate(idright);
}

template<typename T>
void ArithSharing<T>::FinishCircuitLayer() {
#ifdef DEBUGARITH
	if(m_nInputShareRcvCtr > 0) {
		std::cout << "Received "<< m_nInputShareRcvCtr << " input shares: ";
		for(uint32_t i = 0; i < m_nInputShareRcvCtr; i++){
			std::cout << m_vInputShareRcvBuf.template Get<T>(i) << std::endl;
		}
		//m_vInputShareRcvBuf.Print(0, m_nInputShareRcvCtr);
	}
	if(m_nOutputShareRcvCtr > 0) {
		std::cout << "Received " << m_nOutputShareRcvCtr << " output shares: ";
		for(uint32_t i = 0; i < m_nOutputShareRcvCtr; i++){
			std::cout << m_vOutputShareRcvBuf.template Get<T>(i) << std::endl;
		}
		//m_vOutputShareRcvBuf.Print(0, m_nOutputShareRcvCtr);
	}
#endif

	EvaluateMTs();
	EvaluateMULGate();
	AssignInputShares();
	AssignOutputShares();
	AssignConversionShares();

	InitNewLayer();
}

template<typename T>
void ArithSharing<T>::EvaluateMTs() {

	uint32_t startid = m_vMTStartIdx[0];
	uint32_t endid = m_vMTIdx[0];

	T a, b, c, dsnd, esnd, drcv, ercv, e, d, tempres;
	for (uint32_t i = startid; i < endid; i++) {
		a = m_vA[0].template Get<T>(i);
		b = m_vB[0].template Get<T>(i);
		c = m_vC[0].template Get<T>(i);

		dsnd = m_vD_snd[0].template Get<T>(i);
		esnd = m_vE_snd[0].template Get<T>(i);

		drcv = m_vD_rcv[0].template Get<T>(i);
		ercv = m_vE_rcv[0].template Get<T>(i);

		d = (dsnd + drcv) & m_nTypeBitMask;
		e = (esnd + ercv) & m_nTypeBitMask;

		tempres = ((a * e) + (b * d) + c) & m_nTypeBitMask;

		if (m_eRole == SERVER) {
			tempres = (tempres + (d * e)) & m_nTypeBitMask;
		}
#ifdef DEBUGARITH
		std::cout << "mt result = " << (uint64_t) tempres << " = ((" << (uint64_t) a << " * " << (uint64_t) e << " ) + ( " << (uint64_t) b
		<< " * " << (uint64_t) d << ") + " << (uint64_t) c << ")" << std::endl;
#endif
		m_vResA[0].template Set<T>(tempres, i);
	}
}

template<typename T>
void ArithSharing<T>::EvaluateMULGate() {
	GATE* gate;
	for (uint32_t i = 0, idx = m_vMTStartIdx[0]; i < m_vMULGates.size() && idx < m_vMTIdx[0]; i++) {
		gate = m_vMULGates[i];
		InstantiateGate(gate);

		for (uint32_t j = 0; j < gate->nvals; j++, idx++) {
			((T*) gate->gs.aval)[j] = m_vResA[0].template Get<T>(idx);
		}
	}

	m_vMTStartIdx[0] = m_vMTIdx[0];
}

template<typename T>
void ArithSharing<T>::AssignInputShares() {
	GATE* gate;
	for (uint32_t i = 0, rcvshareidx = 0; i < m_vInputShareGates.size(); i++) {
		gate = m_vInputShareGates[i];
		InstantiateGate(gate);

		for (uint32_t j = 0; j < gate->nvals; j++, rcvshareidx++) {
			((T*) gate->gs.aval)[j] = m_vInputShareRcvBuf.template Get<T>(rcvshareidx);
#ifdef DEBUGARITH
			std::cout << "Received inshare: " << (uint64_t) ((T*)gate->gs.aval)[j] << " = " << (uint64_t) m_vInputShareRcvBuf.template Get<T>(rcvshareidx) << std::endl;
#endif
		}
	}
}

template<typename T>
void ArithSharing<T>::AssignOutputShares() {
	GATE* gate;
	for (uint32_t i = 0, rcvshareidx = 0, parentid; i < m_vOutputShareGates.size(); i++) {
		gate = m_vOutputShareGates[i];
		parentid = gate->ingates.inputs.parent;
		InstantiateGate(gate);

		for (uint32_t j = 0; j < gate->nvals; j++, rcvshareidx++) {
			((T*) gate->gs.val)[j] = (((T*) m_vGates[parentid].gs.aval)[j] + m_vOutputShareRcvBuf.template Get<T>(rcvshareidx))
					& m_nTypeBitMask;
#ifdef DEBUGARITH
			std::cout << "Received output share: " << m_vOutputShareRcvBuf.template Get<T>(rcvshareidx) << std::endl;
			std::cout << "Computed output: " << (uint64_t) ((T*)gate->gs.aval)[j] << " = " << (uint64_t) ((T*)m_vGates[parentid].gs.aval)[j] << " + " << (uint64_t) m_vOutputShareRcvBuf.template Get<T>(rcvshareidx) << std::endl;
#endif
		}
		UsedGate(parentid);
	}
}

template<typename T>
void ArithSharing<T>::AssignConversionShares() {
	if (m_eRole == SERVER) {
		// Reset send counter in case we sent something this round
		m_nConvShareSndCtr = 0;
		if (m_nConvShareRcvCtr > 0) {
			AssignServerConversionShares();
		}
	} else {
		if (m_nConvShareRcvCtr > 0) {
			// 2nd round - we received OT data
			AssignClientConversionShares();
		}
		// We sent something this round - prepare next layer and round
		// For server side, this all happens in AssignServerConversionShares
		if (m_nConvShareSndCtr > 0) {
			// Now is 1st round (send) - prepare 2nd round (receive OT data)
			// Backup old index for next round's AssignClientConversionShares
			m_nConvShareIdx2 = m_nConvShareIdx;
			// Increase index for next layer's EvaluateCONVGate
			m_nConvShareIdx += m_nConvShareSndCtr;
			// Need to free 1st vector for possible EvaluateCONVGate gate collection.
			m_vCONVGates2 = m_vCONVGates; // backup for 2nd round
			m_vCONVGates.clear();
			// In round 2 we receive the same amount of data that we just sent.
			m_nConvShareRcvCtr = m_nConvShareSndCtr;
			m_nConvShareSndCtr = 0; // reset for next layer
		}
	}
}

template<typename T>
void ArithSharing<T>::AssignServerConversionShares() {
	// Prepare the send counter. We'll send as much next round as we received this
	// round. Since we consume what was received this round, reset the receive
	// counter.
	m_nConvShareSndCtr = m_nConvShareRcvCtr;
	m_nConvShareRcvCtr = 0;
	// We received conversion shares from the client this round. Now we consume
	// that data and prepare the send buffer for sending the OTs in the next
	// round.
	GATE* gate;
	uint32_t* parentids, clientpermbit;
	uint32_t nparents, nvals;
	T cor, tmpa, tmpb, *tmpsum;

	//Allocate sufficient memory
	uint32_t maxvectorsize = m_pCircuit->GetMaxVectorSize();
	tmpsum = (T*) malloc(sizeof(T) * maxvectorsize);

	for (uint32_t i = 0, lctr = 0, gctr = m_nConvShareIdx; i < m_vCONVGates.size(); i++) {
		gate = m_vCONVGates[i];
		parentids = gate->ingates.inputs.parents;
		nparents = gate->ingates.ningates;
		nvals = gate->nvals;
		memset(tmpsum, 0, sizeof(T) * maxvectorsize);

		for (uint32_t j = 0; j < nparents; j++) {
			for (uint32_t k = 0; k < nvals; k++, lctr++, gctr++) {
				clientpermbit = m_vConvShareRcvBuf.GetBitNoMask(lctr);
				cor = (m_vGates[parentids[j]].gs.val[k / GATE_T_BITS] >> (k % GATE_T_BITS)) & 0x01;
				T rnd = m_vConversionRandomness.template Get<T>(gctr);

				tmpa = (m_nTypeBitMask - (rnd - 1)) + (cor) * (1L << j);
				tmpb = (m_nTypeBitMask - (rnd - 1)) + (!cor) * (1L << j);

				tmpa = m_vConversionMasks[clientpermbit].template Get<T>(gctr) ^ tmpa;
				tmpb = m_vConversionMasks[!clientpermbit].template Get<T>(gctr) ^ tmpb;

				tmpsum[k] += rnd;

#ifdef DEBUGARITH
				std::cout << "Gate " << i << ", " << j << ", " << k << ": " << rnd <<
				", A: " << m_vConversionMasks[clientpermbit].template Get<T>(gctr) << ", " << tmpa <<
				", B: " << m_vConversionMasks[!clientpermbit].template Get<T>(gctr) << ", " << tmpb << ", tmpsum = " << tmpsum[k] << ", gctr = " << gctr << std::endl;
				//std::cout << "gctr = " << gctr << ", nconvmasks = " << m_vConversionMasks[clientpermbit].GetSize() <<", nconvgates = " << m_nNumCONVs << std::endl;
				assert(nvals == 1); // FIXME stupid assertion in debugging
#endif

				m_vConvShareSndBuf.template Set<T>(tmpa, 2 * lctr);
				m_vConvShareSndBuf.template Set<T>(tmpb, 2 * lctr + 1);
			}
			UsedGate(parentids[j]);
		}
		InstantiateGate(gate);
#ifdef DEBUGARITH
		std::cout << "Result for conversion gate: " << i << ": " << std::hex;
#endif
		for (uint32_t k = 0; k < nvals; k++) {
			((T*) gate->gs.aval)[k] = tmpsum[k];
			//std::cout << "Gate val = " << ((T*) gate->gs.aval)[k] << std::endl;
#ifdef DEBUGARITH
			std::cout << tmpsum[k] << " ";
#endif
		}
#ifdef DEBUGARITH
		std::cout << std::endl;
#endif
		free(parentids);
	}
	free(tmpsum);
	// Prepare next round - for client side this happens directly in AssignConversionShares
	m_nConvShareIdx += m_nConvShareSndCtr; // Increment by #gates just received (was moved to SndCtr above)
	m_vCONVGates.clear(); // Clear for next layer's collection in EvaluateCONV
}

template<typename T>
void ArithSharing<T>::AssignClientConversionShares() {
	// Reset - we'll now consume what we received.
	m_nConvShareRcvCtr = 0;
	// We sent conversion shares in the last round and received data from server
	// this round. Unmask the data using values that were precomputed in the OTs
	GATE* gate;
	uint32_t* parentids;
	uint32_t nparents, nvals;
	T rcv, mask, tmp, *tmpsum;

	//Allocate sufficient memory
	uint32_t maxvectorsize = m_pCircuit->GetMaxVectorSize();
	tmpsum = (T*) malloc(sizeof(T) * maxvectorsize);
	//Take the masks from the pre-computed OTs down from the received string
	for (uint32_t i = 0, lctr = 0, gctr = m_nConvShareIdx2; i < m_vCONVGates2.size(); i++) {
		gate = m_vCONVGates2[i];
		parentids = gate->ingates.inputs.parents;
		nparents = gate->ingates.ningates;
		nvals = gate->nvals;
		memset(tmpsum, 0, sizeof(T) * maxvectorsize);

		for (uint32_t j = 0; j < nparents; j++) {
			for (uint32_t k = 0; k < nvals; k++, lctr++, gctr++) {
				rcv = m_vConvShareRcvBuf.template Get<T>(
						(2 * lctr + ((m_vGates[parentids[j]].gs.val[k / GATE_T_BITS] >> (k % GATE_T_BITS)) & 0x01)) );
				mask = m_vConversionMasks[1].template Get<T>(gctr);
				tmp = rcv ^ mask;
				tmpsum[k] += tmp;
#ifdef DEBUGARITH
				std::cout << "Gate " << i << ", " << j << ", " << k << ": " << tmp << " = " << rcv << " ^ " << mask << ", tmpsum = " << tmpsum[k] << ", " <<
				((uint32_t) ((m_vGates[parentids[j]].gs.val[k / GATE_T_BITS] >> (k % GATE_T_BITS)) & 0x01)) << ", gctr = " << gctr << std::endl;
#endif
			}
			UsedGate(parentids[j]);
		}

		InstantiateGate(gate);
#ifdef DEBUGARITH
		std::cout << "Result for conversion gate " << i << ": " << std::hex;
#endif
		for (uint32_t k = 0; k < nvals; k++) {
			((T*) gate->gs.aval)[k] = tmpsum[k];
#ifdef DEBUGARITH
			std::cout << tmpsum[k] << " ";
#endif
		}
#ifdef DEBUGARITH
		std::cout << std::endl;
#endif
		free(parentids);
	}
	free(tmpsum);
	m_vCONVGates2.clear();
}

template<typename T>
void ArithSharing<T>::EvaluateINVGate(GATE* gate) {
	uint32_t parentid = gate->ingates.inputs.parent;
	InstantiateGate(gate);
	for (uint32_t i = 0; i < gate->nvals; i++) {
//			((T*) gate->gs.aval)[i] = MOD_SUB(0, ((T*) m_vGates[parentid].gs.aval)[i], m_nTypeBitMask);//0 - ((T*) m_vGates[parentid].gs.aval)[i];
		((T*) gate->gs.aval)[i] = -((T*) m_vGates[parentid].gs.aval)[i];
	}
	UsedGate(parentid);
}

template<typename T>
void ArithSharing<T>::GetDataToSend(std::vector<BYTE*>& sendbuf, std::vector<uint64_t>& sndbytes) {
	//Input shares
	if (m_nInputShareSndCtr > 0) {
		sendbuf.push_back(m_vInputShareSndBuf.GetArr());
		sndbytes.push_back(m_nInputShareSndCtr * sizeof(T));
	}

	//Output shares
	if (m_nOutputShareSndCtr > 0) {
		sendbuf.push_back(m_vOutputShareSndBuf.GetArr());
		sndbytes.push_back(m_nOutputShareSndCtr * sizeof(T));
	}

	//Conversion shares
	if (m_nConvShareSndCtr > 0) {
		sendbuf.push_back(m_vConvShareSndBuf.GetArr());
		//the client sends shares of his choice bits, the server the masks
		uint32_t snd_bytes = (m_eRole == CLIENT) ?
			ceil_divide(m_nConvShareSndCtr, 8) : 2 * m_nConvShareSndCtr * sizeof(T);
		sndbytes.push_back(snd_bytes);
	}

	uint32_t mtbytelen = (m_vMTIdx[0] - m_vMTStartIdx[0]) * sizeof(T);
	//Selective openings
	if (mtbytelen > 0) {
		sendbuf.push_back(m_vD_snd[0].GetArr() + m_vMTStartIdx[0] * sizeof(T));
		sndbytes.push_back(mtbytelen);
		sendbuf.push_back(m_vE_snd[0].GetArr() + m_vMTStartIdx[0] * sizeof(T));
		sndbytes.push_back(mtbytelen);
	}

#ifdef DEBUGARITH
	if(m_nInputShareSndCtr > 0) {
		std::cout << "Sending " << m_nInputShareSndCtr << " Input shares : ";
		for(uint32_t i = 0; i < m_nInputShareSndCtr; i++) {
			std::cout << m_vInputShareSndBuf.template Get<T>(i) << std::endl;
		}
	}
	if(m_nOutputShareSndCtr > 0) {
		std::cout << "Sending " << m_nOutputShareSndCtr << " Output shares : ";
		for(uint32_t i = 0; i < m_nOutputShareSndCtr; i++){
			std::cout << m_vOutputShareSndBuf.template Get<T>(i) << std::endl;
		}
		//m_vOutputShareSndBuf.Print(0, m_nOutputShareSndCtr);
	}

	if(mtbytelen > 0) {
		std::cout << "Sending 2* " << (m_vMTIdx[0] - m_vMTStartIdx[0]) << " MTs" << std::endl;
	}

	if(m_nConvShareSndCtr > 0) {
		std::cout << "Sending values for	" << m_nConvShareSndCtr << " conversion gates ( " << m_vCONVGates.size() << "gates in total)"<< std::endl;
	}
#endif
}

template<typename T>
void ArithSharing<T>::GetBuffersToReceive(std::vector<BYTE*>& rcvbuf, std::vector<uint64_t>& rcvbytes) {
	//std::cout << "Getting buffers to receive!" << std::endl;
	//Input shares
	if (m_nInputShareRcvCtr > 0) {
		if (m_vInputShareRcvBuf.GetSize() < m_nInputShareRcvCtr * sizeof(T))
			m_vInputShareRcvBuf.ResizeinBytes(m_nInputShareRcvCtr * sizeof(T));
		rcvbuf.push_back(m_vInputShareRcvBuf.GetArr());
		rcvbytes.push_back(m_nInputShareRcvCtr * sizeof(T));
	}

	//Output shares
	if (m_nOutputShareRcvCtr > 0) {
		if (m_vOutputShareRcvBuf.GetSize() < m_nOutputShareRcvCtr * sizeof(T))
			m_vOutputShareRcvBuf.ResizeinBytes(m_nOutputShareRcvCtr * sizeof(T));
		rcvbuf.push_back(m_vOutputShareRcvBuf.GetArr());
		rcvbytes.push_back(m_nOutputShareRcvCtr * sizeof(T));
	}

	//conversion shares
	if (m_nConvShareRcvCtr > 0) {
		//std::cout << "Receiving conversion gate values " << std::endl;
		// SERVER only receives bits, no ot masks
		uint32_t rcv_bytes = (m_eRole == SERVER) ?
			ceil_divide(m_nConvShareRcvCtr, 8) : 2 * m_nConvShareRcvCtr * sizeof(T);
		if (m_vConvShareRcvBuf.GetSize() < rcv_bytes) {
			if (m_eRole == SERVER) {
				m_vConvShareRcvBuf.Create(rcv_bytes * 8, 1);
			} else {
				m_vConvShareRcvBuf.Create(2 * m_nConvShareRcvCtr, m_nTypeBitLen);
			}
		}
		rcvbuf.push_back(m_vConvShareRcvBuf.GetArr());
		rcvbytes.push_back(rcv_bytes);
	}

	uint32_t mtbytelen = (m_vMTIdx[0] - m_vMTStartIdx[0]) * sizeof(T);
	//Selective openings
	if (mtbytelen > 0) {
		rcvbuf.push_back(m_vD_rcv[0].GetArr() + m_vMTStartIdx[0] * sizeof(T));
		rcvbytes.push_back(mtbytelen);
		rcvbuf.push_back(m_vE_rcv[0].GetArr() + m_vMTStartIdx[0] * sizeof(T));
		rcvbytes.push_back(mtbytelen);
	}

#ifdef DEBUGARITH
	if(mtbytelen > 0) {
		std::cout << "Receiving 2* " << (m_vMTIdx[0] - m_vMTStartIdx[0]) << " MTs" << std::endl;
	}

	if(m_nConvShareRcvCtr > 0) {
		std::cout << "Receiving values for	" << m_nConvShareRcvCtr << " conversion gates" << std::endl;
	}
#endif
}

template<typename T>
void ArithSharing<T>::InstantiateGate(GATE* gate) {
	gate->instantiated = true;
	gate->gs.aval = (UGATE_T*) calloc(sizeof(T), gate->nvals);
}

template<typename T>
void ArithSharing<T>::EvaluateSIMDGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	uint32_t vsize = gate->nvals;

	if (gate->type == G_COMBINE) {
#ifdef DEBUGSHARING
		std::cout << " which is a COMBINE gate" << std::endl;
#endif
		uint32_t* input = gate->ingates.inputs.parents;
		uint32_t nparents = gate->ingates.ningates;
		InstantiateGate(gate);

		T* valptr = ((T*) gate->gs.aval);
		for (uint32_t k = 0; k < nparents; k++) {
			memcpy(valptr, m_vGates[input[k]].gs.aval, sizeof(T) * m_vGates[input[k]].nvals);
			valptr += m_vGates[input[k]].nvals;
			UsedGate(input[k]);
		}

		free(input);
	} else if (gate->type == G_SPLIT) {
#ifdef DEBUGSHARING
		std::cout << " which is a SPLIT gate" << std::endl;
#endif
		uint32_t pos = gate->gs.sinput.pos;
		uint32_t idparent = gate->ingates.inputs.parent;
		InstantiateGate(gate);

		for (uint32_t i = 0; i < vsize; i++) {
			((T*) gate->gs.aval)[i] = ((T*) m_vGates[idparent].gs.aval)[pos + i];
		}

		UsedGate(idparent);
	} else if (gate->type == G_REPEAT) {
#ifdef DEBUGSHARING
		std::cout << " which is a REPEATER gate" << std::endl;
#endif
		uint32_t idparent = gate->ingates.inputs.parent; //gate->gs.rinput;
		InstantiateGate(gate);

		for (uint32_t i = 0; i < vsize; i++) {
			((T*) gate->gs.aval)[i] = ((T*) m_vGates[idparent].gs.aval)[0];
		}
		UsedGate(idparent);
	} else if (gate->type == G_PERM) {
#ifdef DEBUGSHARING
		std::cout << " which is a PERMUTATION gate" << std::endl;
#endif
		uint32_t* perm = gate->ingates.inputs.parents;
		uint32_t* pos = gate->gs.perm.posids;

		InstantiateGate(gate);

		//TODO: there might be a problem here since some bits might not be set to zero
		//memset(gate->gs.val, 0x00, ceil_divide(vsize, 8));

		//TODO: Optimize
		for (uint32_t i = 0; i < vsize; i++) {
			((T*) gate->gs.aval)[i] = ((T*) m_vGates[perm[i]].gs.aval)[pos[i]];
			UsedGate(perm[i]);
		}
		free(perm);
		free(pos);
	} else if (gate->type == G_COMBINEPOS) {
#ifdef DEBUGSHARING
		std::cout << " which is a COMBINEPOS gate" << std::endl;
#endif
		uint32_t* combinepos = gate->ingates.inputs.parents;
		uint32_t arraypos = gate->gs.combinepos.pos;
		InstantiateGate(gate);
		//TODO: there might be a problem here since some bits might not be set to zero
		//memset(gate->gs.val, 0x00, ceil_divide(vsize, 8));
		//TODO: Optimize
		for (uint32_t i = 0; i < vsize; i++) {
			uint32_t idparent = combinepos[i];
			((T*) gate->gs.aval)[i] = ((T*) m_vGates[idparent].gs.aval)[arraypos];
			UsedGate(idparent);
		}
		free(combinepos);
	} else if (gate->type == G_SUBSET) {
#ifdef DEBUGSHARING
		std::cout << " which is a SUBSET gate" << std::endl;
#endif
		uint32_t idparent = gate->ingates.inputs.parent;
		uint32_t* positions = gate->gs.sub_pos.posids; //gate->gs.combinepos.input;
		bool del_pos = gate->gs.sub_pos.copy_posids;

		InstantiateGate(gate);

		for (uint32_t i = 0; i < vsize; i++) {
			((T*) gate->gs.aval)[i] = ((T*) m_vGates[idparent].gs.aval)[positions[i]];
		}
		UsedGate(idparent);
		if (del_pos)
			free(positions);
	}
}

#ifdef VERIFY_ARITH_MT
template <typename T>
void ArithSharing<T>::VerifyArithMT(ABYSetup* setup) {
	if(m_nMTs > 0 ) {
		uint32_t MTByteLen = m_nMTs * sizeof(T);
		CBitVector Arcv, Brcv, Crcv;
		BOOL correct = true;
		Arcv.Create(m_nMTs, sizeof(T) * 8);
		Brcv.Create(m_nMTs, sizeof(T) * 8);
		Crcv.Create(m_nMTs, sizeof(T) * 8);

		setup->AddSendTask(m_vA[0].GetArr(), MTByteLen);
		setup->AddReceiveTask(Arcv.GetArr(), MTByteLen);

		setup->AddSendTask(m_vB[0].GetArr(), MTByteLen);
		setup->AddReceiveTask(Brcv.GetArr(), MTByteLen);

		setup->AddSendTask(m_vC[0].GetArr(), MTByteLen);
		setup->AddReceiveTask(Crcv.GetArr(), MTByteLen);

		setup->WaitForTransmissionEnd();

		T a, b, c, res, c1, c2;
		for(uint32_t i = 0; i < m_nMTs; i++) {
			a = m_vA[0].template Get<T>(i) + Arcv.template Get<T>(i);
			b = m_vB[0].template Get<T>(i) + Brcv.template Get<T>(i);
			c = m_vC[0].template Get<T>(i) + Crcv.template Get<T>(i);
			res = a * b;
			if(res != c) {
				std::cerr << "Error: " << i << "-th multiplication triples differs: a (" << (uint64_t) a << ") * b (" <<
				(uint64_t) b << ") = c (" << (uint64_t) c << "), correct = " << (uint64_t) res << std::endl;
				correct = false;
			}
		}
		if(correct) {
			std::cout << "Arithmetic multipilcation triple verification successful" << std::endl;
		}
	}
}
#endif

template<typename T>
uint32_t ArithSharing<T>::AssignInput(CBitVector& inputvals) {
	std::deque<uint32_t> myingates = m_cArithCircuit->GetInputGatesForParty(m_eRole);

	uint32_t ninvals = m_cArithCircuit->GetNumInputBitsForParty(m_eRole) / m_nTypeBitLen;
	inputvals.Create(ninvals, m_nTypeBitLen, m_cCrypto);

	uint32_t typebytes = sizeof(UGATE_T) / sizeof(T);

	GATE* gate;
	for (uint32_t i = 0, inbitctr = 0; i < myingates.size(); i++) {
		gate = &(m_vGates[myingates[i]]);
		if (!gate->instantiated) {

			UGATE_T* inval = (UGATE_T*) calloc(ceil_divide(gate->nvals, typebytes), sizeof(UGATE_T));

			for (uint32_t j = 0; j < gate->nvals; j++) {
				((T*) inval)[j] = inputvals.template Get<T>(inbitctr);
				inbitctr++;
			}
			gate->gs.ishare.inval = inval;
		}
	}
	return m_cArithCircuit->GetNumInputBitsForParty(m_eRole);
}

template<typename T>
uint32_t ArithSharing<T>::GetOutput(CBitVector& out) {

	std::deque<uint32_t> myoutgates = m_cArithCircuit->GetOutputGatesForParty(m_eRole);
	uint32_t outbits = m_cArithCircuit->GetNumOutputBitsForParty(m_eRole);
	out.Create(outbits / m_nTypeBitLen, m_nTypeBitLen);

	GATE* gate;
	for (uint32_t i = 0, outbitctr = 0; i < myoutgates.size(); i++) {
		gate = &(m_vGates[myoutgates[i]]);

		for (uint32_t j = 0; j < gate->nvals; j++) {
			out.template Set<T>(((T*) gate->gs.val)[j], outbitctr);
			outbitctr++;
		}
	}
	return outbits;
}

template<typename T>
void ArithSharing<T>::PrintPerformanceStatistics() {
	std::cout << "Arithmetic Sharing: MULs: " << m_nMTs << " ; Depth: " << GetMaxCommunicationRounds() << std::endl;
}

template<typename T>
void ArithSharing<T>::Reset() {
	assert(m_cArithCircuit->GetNumCONVGates() == m_nConvShareIdx);
	m_nMTs = 0;

	for (uint32_t i = 0; i < m_vMTStartIdx.size(); i++)
		m_vMTStartIdx[i] = 0;
	for (uint32_t i = 0; i < m_vMTIdx.size(); i++)
		m_vMTIdx[i] = 0;
	m_vMULGates.clear();
	m_vInputShareGates.clear();
	m_vOutputShareGates.clear();

	m_nInputShareSndCtr = 0;
	m_nOutputShareSndCtr = 0;

	m_nInputShareRcvCtr = 0;
	m_nOutputShareRcvCtr = 0;

	//TODO if vector multiplication triples are implemented, make size variable
	for (uint32_t i = 0; i < m_vA.size(); i++) {
		m_vA[i].delCBitVector();
		m_vB[i].delCBitVector();
		m_vS[i].delCBitVector();
		m_vD_snd[i].delCBitVector();
		m_vE_snd[i].delCBitVector();
		m_vD_rcv[i].delCBitVector();
		m_vE_rcv[i].delCBitVector();
		m_vResA[i].delCBitVector();
		m_vResB[i].delCBitVector();
	}

	m_vInputShareSndBuf.delCBitVector();
	m_vOutputShareSndBuf.delCBitVector();

	m_vInputShareRcvBuf.delCBitVector();
	m_vOutputShareRcvBuf.delCBitVector();

	m_cArithCircuit->Reset();

	m_nConvShareIdx = 0;
	m_nConvShareIdx2 = 0;
	m_nConvShareSndCtr = 0;
	m_nConvShareRcvCtr = 0;

	m_vCONVGates.clear();
	m_vCONVGates2.clear();
}

//The explicit instantiation part
template class ArithSharing<uint8_t> ;
template class ArithSharing<uint16_t> ;
template class ArithSharing<uint32_t> ;
template class ArithSharing<uint64_t> ;
