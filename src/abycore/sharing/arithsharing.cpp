/**
 \file 		arithsharing.cpp
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
 \brief		Arithmetic Sharing class implementation
 */

#include "arithsharing.h"

template<typename T>
void ArithSharing<T>::Init() {
	m_nMTs = 0;

	m_nTypeBitLen = sizeof(T) * 8;

	memset(&m_nTypeBitMask, 0, sizeof(uint64_t));
	memset(&m_nTypeBitMask, 0xFF, sizeof(T));

	m_cArithCircuit = new ArithmeticCircuit(m_pCircuit, m_eContext, m_eRole, m_nTypeBitLen);

	m_vConversionMasks.resize(2);

	m_nConvShareIdx = 0;
	m_nConvShareSndCtr = 0;
	m_nConvShareRcvCtr = 0;

	m_nInputShareSndCtr = 0;
	m_nOutputShareSndCtr = 0;
	m_nInputShareRcvCtr = 0;
	m_nOutputShareRcvCtr = 0;

	m_vCONVGates.clear();

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
		cout << " m_vInputShareSndBuf at init new layer = ";
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

	ArithMTMasking<T> *fMaskFct = new ArithMTMasking<T>(1, &(m_vB[0])); //TODO to implement the vector multiplication change first argument
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
				IKNP_OTTask* task = (IKNP_OTTask*) malloc(sizeof(IKNP_OTTask));
				task->bitlen = m_nTypeBitLen;
				task->snd_flavor = Snd_C_OT;
				task->rec_flavor = Rec_OT;
				task->numOTs = m_nMTs * m_nTypeBitLen;
				task->mskfct = fMaskFct;
				if ((m_eRole ^ i) == SERVER) {
					task->pval.sndval.X0 = &(m_vC[0]);
					task->pval.sndval.X1 = &(m_vC[0]);
				} else {
					task->pval.rcvval.C = &(m_vA[0]);
					task->pval.rcvval.R = &(m_vS[0]);
				}
#ifndef BATCH
				cout << "Adding a OT task which is supposed to perform " << task->numOTs << " OTs on " << m_nTypeBitLen << " bits for ArithMul" << endl;
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
		task->numOTs = m_nNumCONVs * m_nTypeBitLen;
		task->mskfct = fXORMaskFct;
		if ((m_eRole) == SERVER) {
			m_vConversionMasks[0].Create(m_nNumCONVs * m_nTypeBitLen, m_nTypeBitLen);
			m_vConversionMasks[1].Create(m_nNumCONVs * m_nTypeBitLen, m_nTypeBitLen);
			task->pval.sndval.X0 = &(m_vConversionMasks[0]);
			task->pval.sndval.X1 = &(m_vConversionMasks[1]);
		} else {
			m_vConversionMasks[0].Create((int) m_nNumCONVs * m_nTypeBitLen, m_cCrypto); //the choice bits of the receiver
			m_vConversionMasks[1].Create((int) m_nNumCONVs * m_nTypeBitLen * m_nTypeBitLen); //the resulting masks
			task->pval.rcvval.C = &(m_vConversionMasks[0]);
			task->pval.rcvval.R = &(m_vConversionMasks[1]);
		}
#ifdef DEBUGARITH
		cout << "Conv: Adding a OT task which is supposed to perform " << task->numOTs << " OTs on " << m_nTypeBitLen << " bits for B2A" << endl;
#endif
		setup->AddOTTask(task, 0);

		//Pre-create the buffer
		m_vConvShareSndBuf.Create(2 * m_nNumCONVs * m_nTypeBitLen, m_nTypeBitLen);
		m_vConvShareRcvBuf.Create(2 * m_nNumCONVs * m_nTypeBitLen, m_nTypeBitLen);
		m_vConversionRandomness.Create(m_nNumCONVs * m_nTypeBitLen, m_nTypeBitLen, m_cCrypto);
	}
}

template<typename T>
void ArithSharing<T>::PerformSetupPhase(ABYSetup* setup) {
	//Do nothing
}

template<typename T>
void ArithSharing<T>::FinishSetupPhase(ABYSetup* setup) {
#ifdef DEBUGARITH
	for(uint32_t i = 0; i < m_nMTs; i++) {
		cout << "Output from OT: A: " << (UINT64_T) m_vA[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen) << ", B: " << (UINT64_T) m_vB[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen)
		<< ", C: " << (UINT64_T) m_vC[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen) << ", S: " << (UINT64_T) m_vS[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen) << endl;
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
	cout << " m_vInputShareSndBuf at end of setup phase = ";
	m_vInputShareSndBuf.PrintHex();
#endif
}

template<typename T>
void ArithSharing<T>::InitMTs() {
	m_vMTIdx.resize(1, 0);
	m_vMTStartIdx.resize(1, 0);
	m_vC.resize(1);
	m_vB.resize(1);

	m_vC[0].Create(m_nMTs, m_nTypeBitLen);
	m_vB[0].Create(m_nMTs, m_nTypeBitLen, m_cCrypto);

	m_vA.resize(1);
	m_vS.resize(1);

	m_vA[0].Create(m_nMTs, m_nTypeBitLen, m_cCrypto);
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
	uint32_t bytesMTs = ceil_divide(m_nMTs * m_nTypeBitLen, 8);

	CBitVector temp(m_nMTs);

	T tmp;
	for (uint32_t i = 0; i < m_nMTs; i++) {
		tmp = m_vA[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen) * m_vB[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen);
		tmp += m_vC[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen);
		tmp += m_vS[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen);
		m_vC[0].template Set<T>(tmp, i * m_nTypeBitLen, m_nTypeBitLen);
#ifdef DEBUGARITH
		cout << "Computed MT " << i << ": ";
		cout << "A: " << (UINT64_T) m_vA[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen) << ", B: " << (UINT64_T) m_vB[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen)
		<< ", C: " << (UINT64_T) m_vC[0].template Get<T>(i * m_nTypeBitLen, m_nTypeBitLen) << endl;
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

	uint32_t otherinvals = m_cArithCircuit->GetNumInputBitsForParty(m_eRole==SERVER ? CLIENT : SERVER);
	uint32_t otheroutvals = m_cArithCircuit->GetNumOutputBitsForParty(m_eRole==SERVER ? CLIENT : SERVER);

#ifndef BATCH
	cout << "ninputvals = " << myinvals << ", noutputvals = " << myoutvals << ", typelen = " << m_nTypeBitLen << endl;
#endif

	m_vInputShareSndBuf.Create(myinvals, m_nTypeBitLen, m_cCrypto);
#ifdef DEBUGARITH
	cout << " m_vInputShareSndBuf at prep online phase = ";
	m_vInputShareSndBuf.PrintHex();
#endif

	m_vOutputShareSndBuf.Create(otheroutvals, m_nTypeBitLen);

	m_vInputShareRcvBuf.Create(otherinvals, m_nTypeBitLen);
	m_vOutputShareRcvBuf.Create(myoutvals, m_nTypeBitLen);

	InitNewLayer();
}

template<typename T>
void ArithSharing<T>::EvaluateLocalOperations(uint32_t depth) {
	deque<uint32_t> localops = m_cArithCircuit->GetLocalQueueOnLvl(depth);

	for (uint32_t i = 0; i < localops.size(); i++) {
		GATE* gate = m_pGates + localops[i];

#ifdef DEBUGARITH
		cout << "Evaluating gate with id = " << localops[i] << " of type " << gate->type << endl;
#endif

		if (IsSIMDGate(gate->type)) {
			EvaluateSIMDGate(localops[i]);
		} else if (gate->type == G_LIN) {
#ifdef DEBUGARITH
			cout << " which is an ADD gate" << endl;
#endif
			EvaluateADDGate(gate);
		} else if (gate->type == G_INV) {
#ifdef DEBUGARITH
			cout << " which is an INV gate" << endl;
#endif
			EvaluateINVGate(gate);
		} else if (gate->type == G_CONSTANT) {
			UGATE_T value = gate->gs.constval;
			InstantiateGate(gate);
			if (value > 0 && m_eRole == CLIENT)
				value = 0;
			for (uint32_t i = 0; i < gate->nvals; i++)
				gate->gs.val[i] = value;
		} else if (gate->type == G_CALLBACK) {
			EvaluateCallbackGate(localops[i]);
		} else if (gate->type == G_SHARED_IN) {
			// nothing to do here
		} else if (gate->type == G_SHARED_OUT) {
			GATE* parent = m_pGates + gate->ingates.inputs.parent;
			InstantiateGate(gate);
			memcpy(gate->gs.val, parent->gs.val, gate->nvals * sizeof(T));
			UsedGate(gate->ingates.inputs.parent);
		} else if (gate->type == G_PRINT_VAL) {
			EvaluatePrintValGate(localops[i], C_ARITHMETIC);
		} else if (gate->type == G_ASSERT) {
			EvaluateAssertGate(localops[i], C_ARITHMETIC);
		} else {
			cerr << "Operation not recognized: " << (uint32_t) gate->type << "(" << get_gate_type_name(gate->type) << ")" << endl;
		}
	}
}

template<typename T>
void ArithSharing<T>::EvaluateInteractiveOperations(uint32_t depth) {

	deque<uint32_t> interactiveops = m_cArithCircuit->GetInteractiveQueueOnLvl(depth);

	for (uint32_t i = 0; i < interactiveops.size(); i++) {
		GATE* gate = m_pGates + interactiveops[i];

		if (gate->type == G_NON_LIN) {
#ifdef DEBUGARITH
			cout << " which is an MUL gate" << endl;
#endif
			SelectiveOpen(gate);
		} else if (gate->type == G_IN) {
			if (gate->gs.ishare.src == m_eRole) {
#ifdef DEBUGARITH
				cout << " which is my input gate" << endl;
#endif
				ShareValues(gate);
			} else {
#ifdef DEBUGARITH
				cout << " which is the other parties input gate" << endl;
#endif
				m_vInputShareGates.push_back(gate);
				m_nInputShareRcvCtr += gate->nvals;
			}
		} else if (gate->type == G_OUT) {
			if (gate->gs.oshare.dst == m_eRole) {
#ifdef DEBUGARITH
				cout << " which is my output gate" << endl;
#endif
				m_vOutputShareGates.push_back(gate);
				m_nOutputShareRcvCtr += gate->nvals;
			} else if (gate->gs.oshare.dst == ALL) {
#ifdef DEBUGARITH
				cout << " which is an output gate for both of us" << endl;
#endif
				ReconstructValue(gate);
				m_vOutputShareGates.push_back(gate);
				m_nOutputShareRcvCtr += gate->nvals;
			} else {
#ifdef DEBUGARITH
				cout << " which is the other parties output gate" << endl;
#endif
				ReconstructValue(gate);
			}
		} else if (gate->type == G_CONV) {
#ifdef DEBUGARITH
			cout << " which is a conversion gate" << endl;
#endif
			EvaluateCONVGate(gate);
		} else if (gate->type == G_CALLBACK) {
			EvaluateCallbackGate(interactiveops[i]);
		} else {
			cerr << "Operation not recognized: " << (uint32_t) gate->type << "(" << get_gate_type_name(gate->type) << ")" << endl;
		}
	}
}

template<typename T>
void ArithSharing<T>::EvaluateADDGate(GATE* gate) {
	uint32_t nvals = gate->nvals;
	uint32_t idleft = gate->ingates.inputs.twin.left;
	uint32_t idright = gate->ingates.inputs.twin.right;
	InstantiateGate(gate);

	for (uint32_t i = 0; i < nvals; i++) {
		((T*) gate->gs.aval)[i] = ((T*) m_pGates[idleft].gs.aval)[i] + ((T*) m_pGates[idright].gs.aval)[i];
#ifdef DEBUGARITH
		cout << "Result ADD (" << i << "): "<< ((T*)gate->gs.aval)[i] << " = " << ((T*) m_pGates[idleft].gs.aval)[i] << " + " << ((T*)m_pGates[idright].gs.aval)[i] << endl;
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
	cout << " m_vInputShareSndBuf before inst gate = ";
	m_vInputShareSndBuf.PrintHex();
#endif

	InstantiateGate(gate);

	for (uint32_t i = 0; i < gate->nvals; i++, m_nInputShareSndCtr++) {
		tmpval = m_vInputShareSndBuf.template Get<T>(m_nInputShareSndCtr);
		((T*) gate->gs.aval)[i] = MOD_SUB(input[i], tmpval, m_nTypeBitMask);
#ifdef DEBUGARITH
							cout << "Shared: " << (UINT64_T) ((T*)gate->gs.aval)[i] << " = " << (UINT64_T) input[i] << " - " <<
									(UINT64_T) m_vInputShareSndBuf.template Get<T>(m_nInputShareSndCtr) << ", " << m_nTypeBitMask <<
									", inputid on this layer = " << m_nInputShareSndCtr << ", tmpval = " << tmpval << endl;
							m_vInputShareSndBuf.PrintHex();
#endif
	}
	free(input);
}

template<typename T>
void ArithSharing<T>::EvaluateCONVGate(GATE* gate) {
	uint32_t* parentids = gate->ingates.inputs.parents; //gate->gs.parentgate;
	uint32_t nparents = gate->ingates.ningates;

#ifdef DEBUGARITH
	cout << "Values of B2A gates with id " << ((((uint64_t) gate)-((uint64_t)m_pGates))/sizeof(GATE)) << ": ";
#endif
	for (uint32_t i = 0; i < nparents; i++) {
		if (m_pGates[parentids[i]].context == S_YAO)
			cerr << "can't convert from yao representation directly into arithmetic" << endl;
#ifdef DEBUGARITH
		cout << (uint32_t) m_pGates[parentids[i]].gs.val[0];
#endif

	}
#ifdef DEBUGARITH
	cout << endl;
	cout << "Evaluating conv gate which has " << gate->nvals << " values, current number of conv gates: " << m_vCONVGates.size() << endl;
#endif

	m_vCONVGates.push_back(gate);
	if (m_eRole == SERVER) {
		m_nConvShareRcvCtr += gate->nvals;
	} else {

		//Client routine - receive values
		//copy values into snd buffer
		m_vConvShareSndBuf.SetBytes(m_vConversionMasks[0].GetArr() + (m_nConvShareIdx+m_nConvShareSndCtr) * sizeof(T),
				m_nConvShareSndCtr * sizeof(T), sizeof(T) * gate->nvals);
		for (uint32_t i = 0, ctr = m_nConvShareSndCtr*sizeof(T)*8; i < nparents; i++, ctr += gate->nvals) {
			//XOR the choice bits and the current values of the gate and write into the snd buffer
			m_vConvShareSndBuf.XORBits((BYTE*) m_pGates[parentids[i]].gs.val, ctr, gate->nvals);
		}
#ifdef DEBUGARITH
		cout << "Conversion shares: ";
		m_vConvShareSndBuf.PrintBinary();
#endif
		m_nConvShareSndCtr += gate->nvals;
	}
}

template<typename T>
void ArithSharing<T>::ReconstructValue(GATE* gate) {
	uint32_t parentid = gate->ingates.inputs.parent;

	for (uint32_t i = 0; i < gate->nvals; i++, m_nOutputShareSndCtr++) {
			m_vOutputShareSndBuf.template Set<T>(((T*) m_pGates[parentid].gs.aval)[i], m_nOutputShareSndCtr);
#ifdef DEBUGARITH
				cout << "Sending output share: " << (UINT64_T) ((T*)m_pGates[parentid].gs.aval)[i] << endl;
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
		x = ((T*) m_pGates[idleft].gs.aval)[i];
		d = MOD_SUB(x, a, m_nTypeBitMask); //a > x ? m_nTypeBitMask - (a - 1) + x : x - a;
		m_vD_snd[0].template Set<T>(d, m_vMTIdx[0]);
		b = m_vE_snd[0].template Get<T>(m_vMTIdx[0]);
		y = ((T*) m_pGates[idright].gs.aval)[i];
		e = MOD_SUB(y, b, m_nTypeBitMask); //b > y ? m_nTypeBitMask - (b - 1) + y : y - b;
		m_vE_snd[0].template Set<T>(e, m_vMTIdx[0]);
	}
	m_vMULGates.push_back(gate);

	UsedGate(idleft);
	UsedGate(idright);
}

template<typename T>
void ArithSharing<T>::FinishCircuitLayer(uint32_t depth) {
#ifdef DEBUGARITH
	if(m_nInputShareRcvCtr > 0) {
		cout << "Received "<< m_nInputShareRcvCtr << " input shares: ";
		for(uint32_t i = 0; i < m_nInputShareRcvCtr; i++)
			cout << m_vInputShareRcvBuf.template Get<T>(i) << endl;
		//m_vInputShareRcvBuf.Print(0, m_nInputShareRcvCtr);
	}
	if(m_nOutputShareRcvCtr > 0) {
		cout << "Received " << m_nOutputShareRcvCtr << " output shares: ";
		for(uint32_t i = 0; i < m_nOutputShareRcvCtr; i++)
			cout << m_vOutputShareRcvBuf.template Get<T>(i) << endl;
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
		cout << "mt result = " << (UINT64_T) tempres << " = ((" << (UINT64_T) a << " * " << (UINT64_T) e << " ) + ( " << (UINT64_T) b
		<< " * " << (UINT64_T) d << ") + " << (UINT64_T) c << ")" << endl;
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
			cout << "Received inshare: " << (UINT64_T) ((T*)gate->gs.aval)[j] << " = " << (UINT64_T) m_vInputShareRcvBuf.template Get<T>(rcvshareidx) << endl;
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
			((T*) gate->gs.val)[j] = ((T*) m_pGates[parentid].gs.aval)[j] + m_vOutputShareRcvBuf.template Get<T>(rcvshareidx) & m_nTypeBitMask;
#ifdef DEBUGARITH
			cout << "Received output share: " << m_vOutputShareRcvBuf.template Get<T>(rcvshareidx) << endl;
			cout << "Computed output: " << (UINT64_T) ((T*)gate->gs.aval)[j] << " = " << (UINT64_T) ((T*)m_pGates[parentid].gs.aval)[j] << " + " << (UINT64_T) m_vOutputShareRcvBuf.template Get<T>(rcvshareidx) << endl;
#endif
		}
		UsedGate(parentid);
	}
}

template<typename T>
void ArithSharing<T>::AssignConversionShares() {
	if (m_eRole == SERVER) {
		m_nConvShareSndCtr = 0;
		if (m_nConvShareRcvCtr > 0) {
			AssignServerConversionShares();
		}
	} else {
		if (m_nConvShareRcvCtr > 0) {
			AssignClientConversionShares();
		}
		m_nConvShareRcvCtr = 0;
		if (m_nConvShareSndCtr > 0) {
			m_nConvShareRcvCtr = m_nConvShareSndCtr;
			m_nConvShareSndCtr = 0;
		}
	}
}

template<typename T>
void ArithSharing<T>::AssignServerConversionShares() {
	GATE* gate;
	uint32_t* parentids, clientpermbit;
	uint32_t nparents;
	//I just received conversion shares - send data that was precomputed in the OTs
	m_nConvShareSndCtr = m_nConvShareRcvCtr;
	m_nConvShareRcvCtr = 0;
	T cor, tmpa, tmpb, *tmpsum;

	//Allocate sufficient memory
	uint32_t maxvectorsize = m_pCircuit->GetMaxVectorSize();
	tmpsum = (T*) malloc(sizeof(T) * maxvectorsize);

	for (uint32_t i = 0, lctr = 0, gctr = m_nConvShareIdx * m_nTypeBitLen; i < m_vCONVGates.size(); i++) {
		gate = m_vCONVGates[i];
		parentids = gate->ingates.inputs.parents;
		nparents = gate->ingates.ningates;
		memset(tmpsum, 0, sizeof(T) * maxvectorsize);

		for (uint32_t j = 0; j < nparents; j++) {
			for (uint32_t k = 0; k < m_pGates[parentids[j]].nvals; k++, lctr++, gctr++) {
				clientpermbit = m_vConvShareRcvBuf.GetBitNoMask(lctr);
				cor = (m_pGates[parentids[j]].gs.val[k / GATE_T_BITS] >> (k % GATE_T_BITS)) & 0x01;

				tmpa = (m_nTypeBitMask - (m_vConversionRandomness.template Get<T>(gctr) - 1)) + (cor) * (1L << j);
				tmpb = (m_nTypeBitMask - (m_vConversionRandomness.template Get<T>(gctr) - 1)) + (!cor) * (1L << j);

				tmpa = m_vConversionMasks[clientpermbit].template Get<T>(gctr) ^ tmpa;
				tmpb = m_vConversionMasks[!clientpermbit].template Get<T>(gctr) ^ tmpb;

				tmpsum[k] += m_vConversionRandomness.template Get<T>(gctr);

#ifdef DEBUGARITH
				cout << "Gate " << i << ", " << j << ", " << k << ": " << m_vConversionRandomness.template Get<T>(gctr) <<
						", A: " << m_vConversionMasks[clientpermbit].template Get<T>(gctr) << ", " << tmpa <<
						", B: " << m_vConversionMasks[!clientpermbit].template Get<T>(gctr) << ", " << tmpb << ", tmpsum = " << tmpsum[k] << ", gctr = " << gctr << endl;
				//cout << "gctr = " << gctr << ", nconvmasks = " << m_vConversionMasks[clientpermbit].GetSize() <<", nconvgates = " << m_nNumCONVs << endl;
				assert(gate->nvals == 1);
#endif

				m_vConvShareSndBuf.template Set<T>(tmpa, 2 * lctr);
				m_vConvShareSndBuf.template Set<T>(tmpb, 2 * lctr + 1);
			}
			UsedGate(parentids[j]);
		}
		InstantiateGate(gate);
#ifdef DEBUGARITH
		cout << "Result for conversion gate: ";
#endif
		for (uint32_t k = 0; k < gate->nvals; k++) {
			((T*) gate->gs.aval)[k] = tmpsum[k];
			//cout << "Gate val = " << ((T*) gate->gs.aval)[k] << endl;
#ifdef DEBUGARITH
			cout << tmpsum[k] << " ";
#endif
		}
#ifdef DEBUGARITH
			cout << endl;
#endif
		m_nConvShareIdx += gate->nvals;
		free(parentids);
	}
	free(tmpsum);
	m_vCONVGates.clear();
}

template<typename T>
void ArithSharing<T>::AssignClientConversionShares() {
	//I just sent conversion shares - receive and unmask data using values that were precomputed in the OTs
	GATE* gate;
	uint32_t* parentids;
	uint32_t nparents;
	T rcv, mask, tmp, *tmpsum;

	//Allocate sufficient memory
	uint32_t maxvectorsize = m_pCircuit->GetMaxVectorSize();
	tmpsum = (T*) malloc(sizeof(T) * maxvectorsize);
	//Take the masks from the pre-computed OTs down from the received string
	for (uint32_t i = 0, lctr = 0, gctr = m_nConvShareIdx*m_nTypeBitLen; i < m_vCONVGates.size(); i++, m_nConvShareIdx++) {
		gate = m_vCONVGates[i];
		parentids = gate->ingates.inputs.parents;
		nparents = gate->ingates.ningates;
		memset(tmpsum, 0, sizeof(T) * maxvectorsize);

		for (uint32_t j = 0; j < nparents; j++) {
			for (uint32_t k = 0; k < m_pGates[parentids[j]].nvals; k++, lctr++, gctr++) {
				rcv = m_vConvShareRcvBuf.template Get<T>((2 * lctr + ((m_pGates[parentids[j]].gs.val[k / GATE_T_BITS] >> (k % GATE_T_BITS)) & 0x01)) * m_nTypeBitLen, m_nTypeBitLen);
				mask = m_vConversionMasks[1].template Get<T>(gctr * m_nTypeBitLen, m_nTypeBitLen);
				tmp = rcv ^ mask;
				tmpsum[k] += tmp;
#ifdef DEBUGARITH
				cout << "Gate " << i << ", " << j << ", " << k << ": " << tmp << " = " << rcv << " ^ " << mask << ", tmpsum = " << tmpsum[k] << ", " <<
						((uint32_t) ((m_pGates[parentids[j]].gs.val[k / GATE_T_BITS] >> (k % GATE_T_BITS)) & 0x01)) << ", gctr = " << gctr << endl;
#endif
			}
			UsedGate(parentids[j]);
		}

		InstantiateGate(gate);
#ifdef DEBUGARITH
		cout << "Result for conversion gate: ";
#endif
		for (uint32_t k = 0; k < gate->nvals; k++) {
			((T*) gate->gs.aval)[k] = tmpsum[k];
			//cout << "Gate val = " << ((T*) gate->gs.aval)[k] << endl;
#ifdef DEBUGARITH
			cout << tmpsum[k] << " ";
#endif
		}
#ifdef DEBUGARITH
			cout << endl;
#endif
		free(parentids);
	}
	free(tmpsum);
	m_vCONVGates.clear();
}

template<typename T>
void ArithSharing<T>::EvaluateINVGate(GATE* gate) {
	uint32_t parentid = gate->ingates.inputs.parent;
	InstantiateGate(gate);
	for (uint32_t i = 0; i < gate->nvals; i++) {
//			((T*) gate->gs.aval)[i] = MOD_SUB(0, ((T*) m_pGates[parentid].gs.aval)[i], m_nTypeBitMask);//0 - ((T*) m_pGates[parentid].gs.aval)[i];
		((T*) gate->gs.aval)[i] = -((T*) m_pGates[parentid].gs.aval)[i];
	}
	UsedGate(parentid);
}

template<typename T>
void ArithSharing<T>::GetDataToSend(vector<BYTE*>& sendbuf, vector<uint64_t>& sndbytes) {
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
		if (m_eRole == SERVER) {
			sndbytes.push_back(2 * m_nConvShareSndCtr * sizeof(T) * m_nTypeBitLen);
		} else {
			sndbytes.push_back(ceil_divide(m_nConvShareSndCtr * m_nTypeBitLen, 8));
		}
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
		cout << "Sending " << m_nInputShareSndCtr << " Input shares : ";
		for(uint32_t i = 0; i < m_nInputShareSndCtr; i++)
			cout << m_vInputShareSndBuf.template Get<T>(i) << endl;
	}
	if(m_nOutputShareSndCtr > 0) {
		cout << "Sending " << m_nOutputShareSndCtr << " Output shares : ";
		for(uint32_t i = 0; i < m_nOutputShareSndCtr; i++)
			cout << m_vOutputShareSndBuf.template Get<T>(i) << endl;
		//m_vOutputShareSndBuf.Print(0, m_nOutputShareSndCtr);
	}

	if(mtbytelen > 0) {
		cout << "Sending 2* " << (m_vMTIdx[0] - m_vMTStartIdx[0]) << " MTs" << endl;
	}

	if(m_nConvShareSndCtr > 0) {
		cout << "Sending values for  " << m_nConvShareSndCtr << " conversion gates ( " << m_vCONVGates.size() << "gates in total)"<< endl;
	}
#endif
}

template<typename T>
void ArithSharing<T>::GetBuffersToReceive(vector<BYTE*>& rcvbuf, vector<uint64_t>& rcvbytes) {
	//cout << "Getting buffers to receive!" << endl;
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
		//cout << "Receiving conversion gate values " << endl;
		if (m_vConvShareRcvBuf.GetSize() < m_nConvShareRcvCtr * sizeof(T) * m_nTypeBitLen)
			m_vConvShareRcvBuf.ResizeinBytes(m_nConvShareRcvCtr * sizeof(T) * m_nTypeBitLen);
		rcvbuf.push_back(m_vConvShareRcvBuf.GetArr());
		if (m_eRole == SERVER) {
			rcvbytes.push_back(ceil_divide(m_nConvShareRcvCtr * m_nTypeBitLen, 8));
		} else {
			rcvbytes.push_back(2 * m_nConvShareRcvCtr * sizeof(T) * m_nTypeBitLen);
		}
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
		cout << "Receiving 2* " << (m_vMTIdx[0] - m_vMTStartIdx[0]) << " MTs" << endl;
	}

	if(m_nConvShareRcvCtr > 0) {
		cout << "Receiving values for  " << m_nConvShareRcvCtr << " conversion gates" << endl;
	}
#endif
}

template<typename T>
void ArithSharing<T>::InstantiateGate(GATE* gate) {
	gate->instantiated = true;
	gate->gs.aval = (UGATE_T*) calloc(sizeof(T), gate->nvals);
}

template<typename T>
void ArithSharing<T>::UsedGate(uint32_t gateid) {
	//Decrease the number of further uses of the gate
	m_pGates[gateid].nused--;
	//If the gate is needed in another subsequent gate, delete it
	if (!m_pGates[gateid].nused) {
		free(((T*) m_pGates[gateid].gs.val));
	}
}

template<typename T>
void ArithSharing<T>::EvaluateSIMDGate(uint32_t gateid) {
	GATE* gate = m_pGates + gateid;
	uint32_t vsize = gate->nvals;

	if (gate->type == G_COMBINE) {
#ifdef DEBUGSHARING
		cout << " which is a COMBINE gate" << endl;
#endif
		uint32_t* input = gate->ingates.inputs.parents;
		uint32_t nparents = gate->ingates.ningates;
		InstantiateGate(gate);

		T* valptr = ((T*) gate->gs.aval);
		for(uint32_t k = 0; k < nparents; k++) {
			memcpy(valptr, m_pGates[input[k]].gs.aval, sizeof(T) * m_pGates[input[k]].nvals);
			valptr += m_pGates[input[k]].nvals;
			UsedGate(input[k]);
		}

		free(input);
	} else if (gate->type == G_SPLIT) {
#ifdef DEBUGSHARING
		cout << " which is a SPLIT gate" << endl;
#endif
		uint32_t pos = gate->gs.sinput.pos;
		uint32_t idparent = gate->ingates.inputs.parent;
		InstantiateGate(gate);

		for (uint32_t i = 0; i < vsize; i++) {
			((T*) gate->gs.aval)[i] = ((T*) m_pGates[idparent].gs.aval)[pos + i];
		}

		UsedGate(idparent);
	} else if (gate->type == G_REPEAT)
			{
#ifdef DEBUGSHARING
		cout << " which is a REPEATER gate" << endl;
#endif
		uint32_t idparent = gate->ingates.inputs.parent; //gate->gs.rinput;
		InstantiateGate(gate);

		for (uint32_t i = 0; i < vsize; i++) {
			((T*) gate->gs.aval)[i] = ((T*) m_pGates[idparent].gs.aval)[0];
		}
		UsedGate(idparent);
	} else if (gate->type == G_PERM) {
#ifdef DEBUGSHARING
		cout << " which is a PERMUTATION gate" << endl;
#endif
		uint32_t* perm = gate->ingates.inputs.parents;
		uint32_t* pos = gate->gs.perm.posids;

		InstantiateGate(gate);

		//TODO: there might be a problem here since some bits might not be set to zero
		//memset(gate->gs.val, 0x00, ceil_divide(vsize, 8));

		//TODO: Optimize
		for (uint32_t i = 0; i < vsize; i++) {
			((T*) gate->gs.aval)[i] = ((T*) m_pGates[perm[i]].gs.aval)[pos[i]];
			UsedGate(perm[i]);
		}
		free(perm);
		free(pos);
	} else if (gate->type == G_COMBINEPOS) {
#ifdef DEBUGSHARING
		cout << " which is a COMBINEPOS gate" << endl;
#endif
		uint32_t* combinepos = gate->ingates.inputs.parents;
		uint32_t arraypos = gate->gs.combinepos.pos;
		InstantiateGate(gate);
		//TODO: there might be a problem here since some bits might not be set to zero
		//memset(gate->gs.val, 0x00, ceil_divide(vsize, 8));
		//TODO: Optimize
		for (uint32_t i = 0; i < vsize; i++) {
			uint32_t idparent = combinepos[i];
			gate->gs.aval[i] = ((T*) m_pGates[idparent].gs.aval)[arraypos];
			UsedGate(idparent);
		}
		free(combinepos);
	} else if (gate->type == G_SUBSET) {
#ifdef DEBUGSHARING
		cout << " which is a SUBSET gate" << endl;
#endif
		uint32_t idparent = gate->ingates.inputs.parent;
		uint32_t* positions = gate->gs.sub_pos.posids; //gate->gs.combinepos.input;
		bool del_pos = gate->gs.sub_pos.copy_posids;

		InstantiateGate(gate);

		for (uint32_t i = 0; i < vsize; i++) {
			gate->gs.aval[i] = ((T*) m_pGates[idparent].gs.aval)[positions[i]];
		}
		UsedGate(idparent);
		if(del_pos)
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
				cerr << "Error: " << i << "-th multiplication triples differs: a (" << (UINT64_T) a << ") * b (" <<
				(UINT64_T) b << ") = c (" << (UINT64_T) c << "), correct = " << (UINT64_T) res << endl;
				correct = false;
			}
		}
		if(correct) {
			cout << "Arithmetic multipilcation triple verification successful" << endl;
		}
	}
}
#endif

template<typename T>
uint32_t ArithSharing<T>::AssignInput(CBitVector& inputvals) {
	deque<uint32_t> myingates = m_cArithCircuit->GetInputGatesForParty(m_eRole);

	uint32_t ninvals = m_cArithCircuit->GetNumInputBitsForParty(m_eRole) / m_nTypeBitLen;
	inputvals.Create(ninvals, m_nTypeBitLen, m_cCrypto);

	uint32_t typebytes = sizeof(UGATE_T) / sizeof(T);

	GATE* gate;
	for (uint32_t i = 0, inbitctr = 0; i < myingates.size(); i++) {
		gate = m_pGates + myingates[i];
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

	deque<uint32_t> myoutgates = m_cArithCircuit->GetOutputGatesForParty(m_eRole);
	uint32_t outbits = m_cArithCircuit->GetNumOutputBitsForParty(m_eRole);
	out.Create(outbits / m_nTypeBitLen, m_nTypeBitLen);

	GATE* gate;
	for (uint32_t i = 0, outbitctr = 0; i < myoutgates.size(); i++) {
		gate = m_pGates + myoutgates[i];

		for (uint32_t j = 0; j < gate->nvals; j++) {
			out.template Set<T>(((T*) gate->gs.val)[j], outbitctr);
			outbitctr++;
		}
	}
	return outbits;
}

template<typename T>
void ArithSharing<T>::PrintPerformanceStatistics() {
	cout << "Arithmetic Sharing: MULs: " << m_nMTs << " ; Depth: " << GetMaxCommunicationRounds() << endl;
}

template<typename T>
void ArithSharing<T>::Reset() {
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
	for (uint32_t i = 0; i < 1; i++) {
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
	m_nConvShareSndCtr = 0;
	m_nConvShareRcvCtr = 0;

	m_vCONVGates.clear();
}

//The explicit instantiation part
template class ArithSharing<UINT8_T> ;
template class ArithSharing<UINT16_T> ;
template class ArithSharing<UINT32_T> ;
template class ArithSharing<UINT64_T> ;

