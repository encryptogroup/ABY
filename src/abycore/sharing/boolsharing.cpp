/**
 \file 		boolsharing.cpp
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
 \brief		Bool sharing class implementation.
 */
#include "boolsharing.h"

void BoolSharing::Init() {

	m_nTotalNumMTs = 0;
	m_nXORGates = 0;

	m_nNumANDSizes = 0;

	m_nInputShareSndSize = 0;
	m_nOutputShareSndSize = 0;

	m_nInputShareRcvSize = 0;
	m_nOutputShareRcvSize = 0;

	m_cBoolCircuit = new BooleanCircuit(m_pCircuit, m_eRole, S_BOOL);
}

//Pre-set values for new layer
void BoolSharing::InitNewLayer() {
	//Create new random values for this layer
	if (m_nInputShareSndSize > 0) {
		uint32_t inbits = m_cBoolCircuit->GetNumInputBitsForParty(m_eRole);
		m_vInputShareSndBuf.Create(inbits, m_cCrypto);
	}

	m_nInputShareRcvSize = 0;
	m_nOutputShareRcvSize = 0;

	m_nInputShareSndSize = 0;
	m_nOutputShareSndSize = 0;

	for (uint32_t i = 0; i < m_vANDGates.size(); i++)
		m_vANDGates[i].clear();

	m_vInputShareGates.clear();
	m_vOutputShareGates.clear();

}

void BoolSharing::PrepareSetupPhase(ABYSetup* setup) {
	m_nNumANDSizes = m_cBoolCircuit->GetANDs(m_vANDs);

	m_nTotalNumMTs = 0;
	m_nNumMTs.resize(m_nNumANDSizes);
	for (uint32_t i = 0; i < m_nNumANDSizes; i++) {
		//Is needed to pad the MTs to a byte, deleting this will make the online phase really messy and (probably) inefficient
		m_nNumMTs[i] = m_vANDs[i].numgates + (8 * m_cBoolCircuit->GetMaxDepth());
		m_nTotalNumMTs += m_vANDs[i].numgates;
	}

	//8*circuit_depth are needed since the mtidx is padded to the next byte after each layer
	if (m_nTotalNumMTs > 0)
		m_nTotalNumMTs += (8 * m_cBoolCircuit->GetMaxDepth());

	InitializeMTs();

	if (m_nTotalNumMTs == 0)
		return;

	for (uint32_t i = 0; i < m_nNumANDSizes; i++) {
		fMaskFct = new XORMasking(m_vANDs[i].bitlen);

		for (uint32_t j = 0; j < 2; j++) {
			OTTask* task = (OTTask*) malloc(sizeof(OTTask));
			task->bitlen = m_vANDs[i].bitlen;
			task->ottype = R_OT;
			task->numOTs = m_nNumMTs[i];
			task->mskfct = fMaskFct;
			if ((m_eRole ^ j) == SERVER) {
				task->pval.sndval.X0 = &(m_vC[i]);
				task->pval.sndval.X1 = &(m_vB[i]);
			} else {
				task->pval.rcvval.C = &(m_vA[i]);
				task->pval.rcvval.R = &(m_vS[i]);
			}
#ifndef BATCH
			cout << "Adding new OT task for " << m_nNumMTs[i] << " OTs on " << m_vANDs[i].bitlen << " bit-strings" << endl;
#endif
			setup->AddOTTask(task, j);
		}
	}

}

void BoolSharing::PerformSetupPhase(ABYSetup* setup) {
	//Do nothing
}
void BoolSharing::FinishSetupPhase(ABYSetup* setup) {
	if (m_nTotalNumMTs == 0)
		return;

	//Compute Multiplication Triples
	ComputeMTs();
#ifdef DEBUGBOOL
	cout << "A: ";
	m_vA[0].PrintBinary();
	cout << "B: ";
	m_vB[0].PrintBinary();
	cout << "C: ";
	m_vC[0].PrintBinary();
#endif
}

void BoolSharing::InitializeMTs() {
	m_vMTIdx.resize(m_nNumANDSizes, 0);
	m_vMTStartIdx.resize(m_nNumANDSizes, 0);

	m_vC.resize(m_nNumANDSizes);
	m_vB.resize(m_nNumANDSizes);

	m_vA.resize(m_nNumANDSizes);
	m_vS.resize(m_nNumANDSizes);

	m_vD_snd.resize(m_nNumANDSizes);
	m_vE_snd.resize(m_nNumANDSizes);
	m_vD_rcv.resize(m_nNumANDSizes);
	m_vE_rcv.resize(m_nNumANDSizes);

	m_vResA.resize(m_nNumANDSizes);
	m_vResB.resize(m_nNumANDSizes);

	for (uint32_t i = 0; i < m_nNumANDSizes; i++) {
		//A contains the  choice bits for the OTs
		m_vA[i].Create(m_nNumMTs[i], m_cCrypto);
		//B contains the correlation between the OTs
		m_vB[i].Create(m_nNumMTs[i] * m_vANDs[i].bitlen);
		//C contains the zero mask and is later computed correctly
		m_vC[i].Create(m_nNumMTs[i] * m_vANDs[i].bitlen);
		//S is a temporary buffer and contains the result of the OTs where A is used as choice bits
		m_vS[i].Create(m_nNumMTs[i] * m_vANDs[i].bitlen);

		//TODO: might be optimizable if the buffers are only allocated in the size of each layer
		//D snd and rcv contain the masked A values
		m_vD_snd[i].Create(m_nNumMTs[i]);
		m_vD_rcv[i].Create(m_nNumMTs[i]);
		//E contains the masked B values
		m_vE_snd[i].Create(m_nNumMTs[i] * m_vANDs[i].bitlen);
		m_vE_rcv[i].Create(m_nNumMTs[i] * m_vANDs[i].bitlen);
		//ResA and ResB are temporary results
		m_vResA[i].Create(m_nNumMTs[i] * m_vANDs[i].bitlen);
		m_vResB[i].Create(m_nNumMTs[i] * m_vANDs[i].bitlen);
	}
}

void BoolSharing::PrepareOnlinePhase() {

	//get #in/output bits for other party
	uint32_t insharesndbits = m_cBoolCircuit->GetNumInputBitsForParty(m_eRole==SERVER ? CLIENT : SERVER);
	uint32_t outsharesndbits = m_cBoolCircuit->GetNumOutputBitsForParty(m_eRole==SERVER ? CLIENT : SERVER);

	//TODO: more clever size finding since this may not be known initially
	m_vInputShareSndBuf.Create(insharesndbits, m_cCrypto);

	m_vOutputShareSndBuf.Create(outsharesndbits);
	m_vInputShareRcvBuf.Create(MAXSHAREBUFSIZE);
	m_vOutputShareRcvBuf.Create(MAXSHAREBUFSIZE);

	m_vANDGates.resize(m_nNumANDSizes);

	InitNewLayer();

}

void BoolSharing::ComputeMTs() {
	for (uint32_t i = 0; i < m_nNumANDSizes; i++) {
		uint32_t andbytelen = ceil_divide(m_nNumMTs[i], 8);
		uint32_t stringbytelen = ceil_divide(m_nNumMTs[i] * m_vANDs[i].bitlen, 8);

		CBitVector temp(stringbytelen * 8);
		temp.Reset();

		//Get correct B
		m_vB[i].XORBytes(m_vC[i].GetArr(), 0, stringbytelen);

		//Compute the correct C
		if (m_vANDs[i].bitlen == 1) { //for bits
			temp.SetAND(m_vA[i].GetArr(), m_vB[i].GetArr(), 0, andbytelen);
		} else if (m_vANDs[i].bitlen & 0x07 == 0) { //for bytes
			uint32_t elebytelen = ceil_divide(m_vANDs[i].bitlen, 8);
			for (uint32_t j = 0, byteidx = 0; j < m_nNumMTs[i]; j++, byteidx += elebytelen) {
				if (m_vA[i].GetBitNoMask(j)) {
					temp.SetBytes(m_vB[i].GetArr() + byteidx, byteidx, elebytelen);
				}
			}
		} else { //for arbitrary length values
			uint32_t elebitlen = m_vANDs[i].bitlen;
			for (uint32_t j = 0, bitidx = 0; j < m_nNumMTs[i]; j++, bitidx += elebitlen) {
				if (m_vA[i].GetBitNoMask(j)) {
					temp.SetBitsPosOffset(m_vB[i].GetArr(), bitidx, bitidx, elebitlen);
				}
			}
		}


		m_vC[i].XORBytes(temp.GetArr(), 0, stringbytelen);
		m_vC[i].XORBytes(m_vS[i].GetArr(), 0, stringbytelen);

		//Pre-store the values in A and B in D_snd and E_snd
		m_vD_snd[i].Copy(m_vA[i].GetArr(), 0, andbytelen);
		m_vE_snd[i].Copy(m_vB[i].GetArr(), 0, stringbytelen);

#ifdef DEBUGBOOL
		cout << "MT types for bitlen: " << m_vANDs[i].bitlen << endl;
		cout << "A: ";
		m_vA[i].PrintBinary();
		cout << "B: ";
		m_vB[i].PrintHex();
		cout << "C: ";
		m_vC[i].PrintHex();
#endif
	}

}

void BoolSharing::EvaluateLocalOperations(uint32_t depth) {
	deque<uint32_t> localops = m_cBoolCircuit->GetLocalQueueOnLvl(depth);
	GATE* gate;

	for (uint32_t i = 0; i < localops.size(); i++) {
		gate = m_pGates + localops[i];

#ifdef DEBUGBOOL
		cout << "Evaluating local gate with id = " << localops[i] << " and type " << get_gate_type_name(gate->type) << endl;
#endif

		switch (gate->type) {
		case G_LIN:
			EvaluateXORGate(localops[i]);
			break;
		case G_CONSTANT:
			EvaluateConstantGate(localops[i]);
			break;
		case G_INV:
			EvaluateINVGate(localops[i]);
			break;
		case G_CONV:
			EvaluateCONVGate(localops[i]);
			break;
		case G_CALLBACK:
			EvaluateCallbackGate(localops[i]);
			break;
		default:
			if (IsSIMDGate(gate->type)) {
				EvaluateSIMDGate(localops[i]);
			} else {
				cerr << "Non-interactive Operation not recognized: " << (uint32_t) gate->type << "(" << get_gate_type_name(gate->type) << "), stopping execution" << endl;
				exit(0);
			}
			break;
		}
	}
}

void BoolSharing::EvaluateInteractiveOperations(uint32_t depth) {
	deque<uint32_t> interactiveops = m_cBoolCircuit->GetInteractiveQueueOnLvl(depth);

	for (uint32_t i = 0; i < interactiveops.size(); i++) {
		GATE* gate = m_pGates + interactiveops[i];

#ifdef DEBUGBOOL
		cout << "Evaluating interactive gate with id = " << interactiveops[i] << " and type " << get_gate_type_name(gate->type) << endl;
#endif

		switch (gate->type) {
		case G_NON_LIN:
			SelectiveOpen(interactiveops[i]);
			break;
		case G_NON_LIN_VEC:
			SelectiveOpenVec(interactiveops[i]);
			break;
		case G_IN:
			if (gate->gs.ishare.src == m_eRole) {
				ShareValues(interactiveops[i]);
			} else {
				m_vInputShareGates.push_back(interactiveops[i]);
				m_nInputShareRcvSize += gate->nvals;
			}
			break;
		case G_OUT:
			if (gate->gs.oshare.dst == m_eRole) {
				m_vOutputShareGates.push_back(interactiveops[i]);
				m_nOutputShareRcvSize += gate->nvals;
			} else if (gate->gs.oshare.dst == ALL) {
				ReconstructValue(interactiveops[i]);
				m_vOutputShareGates.push_back(interactiveops[i]);
				m_nOutputShareRcvSize += gate->nvals;
			} else {
				ReconstructValue(interactiveops[i]);
			}
			break;
		case G_CALLBACK:
			EvaluateCallbackGate(interactiveops[i]);
			break;
		default:
			cerr << "Interactive Operation not recognized: " << (uint32_t) gate->type << " (" << get_gate_type_name(gate->type) << "), stopping execution" << endl;
			exit(0);
		}
	}
}

inline void BoolSharing::EvaluateXORGate(uint32_t gateid) {
	GATE* gate = m_pGates + gateid;
	uint32_t nvals = gate->nvals;
	uint32_t idleft = gate->ingates.inputs.twin.left;
	uint32_t idright = gate->ingates.inputs.twin.right;
	InstantiateGate(gate);

	for (uint32_t i = 0; i < ceil_divide(nvals, GATE_T_BITS); i++) {
		gate->gs.val[i] = m_pGates[idleft].gs.val[i] ^ m_pGates[idright].gs.val[i];
	}

	UsedGate(idleft);
	UsedGate(idright);
}

inline void BoolSharing::EvaluateConstantGate(uint32_t gateid) {
	GATE* gate = m_pGates + gateid;
	UGATE_T value = gate->gs.constval;
	InstantiateGate(gate);
	value = value * (m_eRole != CLIENT);

	for (uint32_t i = 0; i < ceil_divide(gate->nvals, GATE_T_BITS); i++) {
		gate->gs.val[i] = value;
	}
#ifdef DEBUGBOOL
		cout << "Constant gate value: "<< value << endl;
#endif
}


inline void BoolSharing::ShareValues(uint32_t gateid) {
	GATE* gate = m_pGates + gateid;
	UGATE_T* input = gate->gs.ishare.inval;
	InstantiateGate(gate);

	for (uint32_t i = 0, bitstocopy = gate->nvals, len; i < ceil_divide(gate->nvals, GATE_T_BITS); i++, bitstocopy -= GATE_T_BITS) {
		len = min(bitstocopy, (uint32_t) GATE_T_BITS);
		gate->gs.val[i] = m_vInputShareSndBuf.Get<UGATE_T>(m_nInputShareSndSize, len) ^ input[i];
#ifdef DEBUGBOOL
		cout << (unsigned uint32_t) gate->gs.val[i] << " = " << (unsigned uint32_t) m_vInputShareSndBuf.Get<UGATE_T>(m_nInputShareSndSize, len) << " ^ " << (unsigned uint32_t) input[i] << endl;
#endif
		m_nInputShareSndSize += len;
	}

	free(input);
}

inline void BoolSharing::EvaluateINVGate(uint32_t gateid) {
	GATE* gate = m_pGates + gateid;
	uint32_t parentid = gate->ingates.inputs.parent;
	uint32_t i;
	InstantiateGate(gate);
	UGATE_T tmpval;
	if (m_eRole == SERVER) {
		memset(&tmpval, 0xFF, sizeof(UGATE_T));
	} else {
		memset(&tmpval, 0x00, sizeof(UGATE_T));
	}
	for (i = 0; i < ceil_divide((gate->nvals+1), GATE_T_BITS) - 1; i++) {
		gate->gs.val[i] = m_pGates[parentid].gs.val[i] ^ tmpval;
	}
	//set only the remaining nvals%GATE_T_BITS
	gate->gs.val[i] = (m_pGates[parentid].gs.val[i] ^ tmpval) & (((UGATE_T) 1) << ((gate->nvals % GATE_T_BITS))) - 1;
#ifdef DEBUGBOOL
	cout << "Evaluated INV gate " << gateid << " with result: " << (hex) << gate->gs.val[0] <<
	" and input: " << m_pGates[parentid].gs.val[0]<< (dec) << endl;
#endif
	UsedGate(parentid);
}

inline void BoolSharing::EvaluateCONVGate(uint32_t gateid) {
	GATE* gate = m_pGates + gateid;
	uint32_t parentid = gate->ingates.inputs.parents[0];
	if (m_pGates[parentid].context == S_ARITH)
		cerr << "can't convert from arithmetic representation directly into Boolean" << endl;
	InstantiateGate(gate);

	memset(gate->gs.val, 0, ceil_divide(gate->nvals, 8));
	if (m_eRole == SERVER) {
		for (uint32_t i = 0; i < gate->nvals; i++) {
			gate->gs.val[i / GATE_T_BITS] |= m_pGates[parentid].gs.yinput.pi[i] << (i % GATE_T_BITS);
		}
	} else {
		for (uint32_t i = 0; i < gate->nvals; i++) {
			gate->gs.val[i / GATE_T_BITS] |= ((m_pGates[parentid].gs.yval[((i + 1) * m_nSecParamBytes) - 1] & 0x01) << (i % GATE_T_BITS));
		}
	}
#ifdef DEBUGBOOL
	cout << "Set conversion gate value to " << gate->gs.val[0] << endl;
#endif

	UsedGate(parentid);
}

inline void BoolSharing::ReconstructValue(uint32_t gateid) {
	GATE* gate = m_pGates + gateid;
	uint32_t parentid = gate->ingates.inputs.parent;

	for (uint32_t i = 0, bitstocopy = gate->nvals, len; i < ceil_divide(gate->nvals, GATE_T_BITS); i++, bitstocopy -= GATE_T_BITS) {
		len = min(bitstocopy, (uint32_t) GATE_T_BITS);
#ifdef DEBUGBOOL
		cout << "m_vOutputShareSndBuf.size = " << m_vOutputShareSndBuf.GetSize() << ", ctr = " <<m_nOutputShareSndSize << ", len = " << len << ", gate->parent = " << parentid
		<< " and val = " << (hex) << m_pGates[parentid].gs.val[i] << (dec) << endl;
#endif
		m_vOutputShareSndBuf.Set<UGATE_T>(m_pGates[parentid].gs.val[i], m_nOutputShareSndSize, len);	//gate->gs.val[i], len);
		m_nOutputShareSndSize += len;
	}
	if (gate->gs.oshare.dst != ALL)
		UsedGate(parentid);
}

inline void BoolSharing::SelectiveOpen(uint32_t gateid) {
	GATE* gate = m_pGates + gateid;
	uint32_t idleft = gate->ingates.inputs.twin.left;
	uint32_t idright = gate->ingates.inputs.twin.right;

	for (uint32_t i = 0, bitstocopy = gate->nvals, len; i < ceil_divide(gate->nvals, GATE_T_BITS); i++, bitstocopy -= GATE_T_BITS) {
		len = min(bitstocopy, (uint32_t) GATE_T_BITS);
		m_vD_snd[0].XOR(m_pGates[idleft].gs.val[i], m_vMTIdx[0], len);
		m_vE_snd[0].XOR(m_pGates[idright].gs.val[i], m_vMTIdx[0], len);
		m_vMTIdx[0] += len;
#ifdef DEBUGBOOL
		cout << "opening " << idleft << " = " << m_pGates[idleft].gs.val[i] << " , and " << idright << " = " << m_pGates[idright].gs.val[i] << endl;
#endif
	}
	m_vANDGates[0].push_back(gateid);

	UsedGate(idleft);
	UsedGate(idright);
}

//TODO: enable SIMD operations for VEC_ANDs
inline void BoolSharing::SelectiveOpenVec(uint32_t gateid) {
	GATE* gate = m_pGates + gateid;
	uint32_t idchoice = gate->ingates.inputs.twin.left;
	uint32_t idvector = gate->ingates.inputs.twin.right;

	uint32_t pos = FindBitLenPositionInVec(gate->nvals, m_vANDs, m_nNumANDSizes);
	uint32_t startpos = m_vMTIdx[pos] * m_vANDs[pos].bitlen;
	//XOR the choice bit onto the D-vector
	m_vD_snd[pos].XORBitNoMask(m_vMTIdx[pos], m_pGates[idchoice].gs.val[0]);

	//cout << "choice_val: " << m_pGates[idchoice].gs.val[0] << ", vec_val: " << m_pGates[idvector].gs.val[0] << " (" << gateid << ")" << endl;
	//for (uint32_t i = 0, bitstocopy = gate->nvals * m_vANDs[pos].bitlen, ncopiedvals; i < ceil_divide(gate->nvals, GATE_T_BITS); i++, bitstocopy -= GATE_T_BITS) {
	for (uint32_t i = 0, bitstocopy = gate->nvals, ncopiedvals; i < ceil_divide(gate->nvals, GATE_T_BITS); i++, bitstocopy -= GATE_T_BITS, startpos+=GATE_T_BITS) {
		ncopiedvals = min(bitstocopy, (uint32_t) GATE_T_BITS);
		//m_vE_snd[pos].XOR(m_pGates[idvector].gs.val[i], m_vMTIdx[pos] * m_vANDs[pos].bitlen, ncopiedvals); //*m_vANDs[pos].bitlen);
		m_vE_snd[pos].XOR(m_pGates[idvector].gs.val[i], startpos, ncopiedvals); //*m_vANDs[pos].bitlen);
#ifdef DEBUGBOOL
		cout << "copying from " << m_vMTIdx[pos]*m_vANDs[pos].bitlen << " with len = " << ncopiedvals << endl;

		cout << "choice-gate " << idchoice << " = " << m_pGates[idchoice].gs.val[0] << " , and vec-gate " << idvector <<
		" = " <<(hex) << m_pGates[idvector].gs.val[i] << (dec) << endl;
#endif
	}
	m_vMTIdx[pos]++;

	m_vANDGates[pos].push_back(gateid);

	UsedGate(idchoice);
	UsedGate(idvector);
}

void BoolSharing::FinishCircuitLayer() {
	//Compute the values of the AND gates
#ifdef DEBUGBOOL
	if(m_nInputShareRcvSize > 0) {
		cout << "Received "<< m_nInputShareRcvSize << " input shares: ";
		m_vInputShareRcvBuf.Print(0, m_nInputShareRcvSize);
	}
	if(m_nOutputShareRcvSize > 0) {
		cout << "Received " << m_nOutputShareRcvSize << " output shares: ";
		m_vOutputShareRcvBuf.Print(0, m_nOutputShareRcvSize);
	}
#endif

	EvaluateMTs();
	EvaluateANDGate();
	AssignInputShares();
	AssignOutputShares();

	InitNewLayer();
}

void BoolSharing::EvaluateMTs() {
	for (uint32_t i = 0; i < m_nNumANDSizes; i++) {
		uint32_t startpos = m_vMTStartIdx[i];
		uint32_t endpos = m_vMTIdx[i];
		uint32_t len = endpos - startpos;
		uint32_t startposbytes = ceil_divide(startpos, 8);
		uint32_t startposstringbits = startpos * m_vANDs[i].bitlen;
		uint32_t startposstringbytes = startposbytes * m_vANDs[i].bitlen;
		uint32_t lenbytes = ceil_divide(len, 8);
		uint32_t stringbytelen = ceil_divide(m_vANDs[i].bitlen * len, 8);
		uint32_t mtbytelen = ceil_divide(m_vANDs[i].bitlen, 8);

		m_vD_snd[i].XORBytes(m_vD_rcv[i].GetArr() + startposbytes, startposbytes, lenbytes);
		m_vE_snd[i].XORBytes(m_vE_rcv[i].GetArr() + startposstringbytes, startposstringbytes, stringbytelen);

#ifdef DEBUGBOOL
		if(i > 0) {
		cout << "lenbytes = " << lenbytes << ", stringlen = " << stringbytelen << ", mtbytelen = " << mtbytelen <<
		", startposbytes = " << startposbytes << ", startposstring = " << startposstringbytes << endl;


		cout << "A share: ";
		m_vA[i].Print(0, len);
		cout << "B share: ";
		m_vB[i].PrintHex(0, stringbytelen);
		cout << "C-share: ";
		m_vC[i].PrintHex(0, stringbytelen);

		cout << "D-rcv: ";
		m_vD_rcv[i].Print(0,len);
		cout << "E-rcv: ";
		m_vE_rcv[i].PrintHex(0, stringbytelen);
		cout << "D-total: ";
		m_vD_snd[i].Print(0,len);
		cout << "E-total: ";
		m_vE_snd[i].PrintHex(0, stringbytelen);
		}
#endif

		if (i == 0) {
			m_vResA[i].Copy(m_vA[i].GetArr() + startposbytes, startposbytes, lenbytes);
			m_vResB[i].Copy(m_vB[i].GetArr() + startposbytes, startposbytes, lenbytes);

			m_vResA[i].ANDBytes(m_vE_snd[i].GetArr() + startposbytes, startposbytes, lenbytes);
			m_vResB[i].ANDBytes(m_vD_snd[i].GetArr() + startposbytes, startposbytes, lenbytes);
		} else {
			if((m_vANDs[i].bitlen & 0x07) == 0) {
				for (uint32_t j = 0; j < len; j++) {
					if (m_vA[i].GetBitNoMask(j + startpos)) { //a * e
						m_vResA[i].SetBytes(m_vE_snd[i].GetArr() + startposstringbytes + j * mtbytelen,
								startposstringbytes + j * mtbytelen, mtbytelen);
					}
					if (m_vD_snd[i].GetBitNoMask(j + startpos)) { //d * b
						m_vResB[i].SetBytes(m_vB[i].GetArr() + startposstringbytes + j * mtbytelen,
								startposstringbytes + j * mtbytelen, mtbytelen);
					}
				}
			} else {
				for (uint32_t j = 0; j < len; j++) {
					if (m_vA[i].GetBitNoMask(j + startpos)) { //a * e
						uint64_t tmp = m_vE_snd[i].Get<uint64_t>(startposstringbits + j*m_vANDs[i].bitlen, m_vANDs[i].bitlen);
						m_vResA[i].Set<uint64_t>(tmp, startposstringbits + j*m_vANDs[i].bitlen, m_vANDs[i].bitlen);
						//m_vResA[i].SetBitsPosOffset(m_vE_snd[i].GetArr(), startposstringbits + j * m_vANDs[i].bitlen,
						//		startposstringbits + j * m_vANDs[i].bitlen, m_vANDs[i].bitlen);
					}
					if (m_vD_snd[i].GetBitNoMask(j + startpos)) { //d * b
						uint64_t tmp = m_vB[i].Get<uint64_t>(startposstringbits + j*m_vANDs[i].bitlen, m_vANDs[i].bitlen);
						m_vResB[i].Set<uint64_t>(tmp, startposstringbits + j*m_vANDs[i].bitlen, m_vANDs[i].bitlen);
						//m_vResB[i].SetBitsPosOffset(m_vB[i].GetArr(), startposstringbits + j * m_vANDs[i].bitlen,
						//		startposstringbits + j * m_vANDs[i].bitlen, m_vANDs[i].bitlen);
					}
				}
			}
		}

		m_vResA[i].XORBytes(m_vResB[i].GetArr() + startposstringbytes, startposstringbytes, stringbytelen);
		m_vResA[i].XORBytes(m_vC[i].GetArr() + startposstringbytes, startposstringbytes, stringbytelen);

		if (m_eRole == SERVER) {
			if (i == 0) {
				m_vResB[i].Copy(m_vE_snd[i].GetArr() + startposbytes, startposbytes, lenbytes);
				m_vResB[i].ANDBytes(m_vD_snd[i].GetArr() + startposbytes, startposbytes, lenbytes);
			} else {
				if((m_vANDs[i].bitlen & 0x07) == 0) {
					for (uint32_t j = 0; j < len; j++) {
						if (m_vD_snd[i].GetBitNoMask(j + startpos)) { //d * e
							m_vResB[i].SetBytes(m_vE_snd[i].GetArr() + startposstringbytes + j * mtbytelen,
									startposstringbytes + j * mtbytelen, mtbytelen);
						}
					}
				} else {
					for (uint32_t j = 0; j < len; j++) {
						if (m_vD_snd[i].GetBitNoMask(j + startpos)) { //d * e
							uint64_t tmp = m_vE_snd[i].Get<uint64_t>(startposstringbits + j*m_vANDs[i].bitlen, m_vANDs[i].bitlen);
							m_vResB[i].Set<uint64_t>(tmp, startposstringbits + j*m_vANDs[i].bitlen, m_vANDs[i].bitlen);
							//m_vResB[i].SetBitsPosOffset(m_vE_snd[i].GetArr(), startposstringbits + j * m_vANDs[i].bitlen,
							//		startposstringbits + j * m_vANDs[i].bitlen, m_vANDs[i].bitlen);
						}
					}
				}
			}
			m_vResA[i].XORBytes(m_vResB[i].GetArr() + startposstringbytes, startposstringbytes, stringbytelen);
		}
	}
}

void BoolSharing::EvaluateANDGate() {
	GATE* gate;
	for (uint32_t k = 0; k < m_nNumANDSizes; k++) {
		for (uint32_t i = 0, j, bitstocopy, len, idx = m_vMTStartIdx[k]*m_vANDs[k].bitlen; i < m_vANDGates[k].size(); i++) {
			gate = m_pGates + m_vANDGates[k][i];
			InstantiateGate(gate);

			bitstocopy = gate->nvals;

			for (j = 0; j < ceil_divide(gate->nvals, GATE_T_BITS); j++, bitstocopy -= GATE_T_BITS) {
				len = min(bitstocopy, (uint32_t) GATE_T_BITS);

#ifdef DEBUGBOOL
				m_vResA[k].PrintHex();

				cout << "setting AND gate " << m_vANDGates[k][i] << " with val-size = " << gate->nvals <<
				", sharinbits = " << gate->sharebitlen << ", and bitstocopy = " << bitstocopy <<
				" to value: " << (hex) << m_vResA[k].Get<UGATE_T>(idx, len) << (dec) << endl;
#endif
				gate->gs.val[j] = m_vResA[k].Get<UGATE_T>(idx, len);
				/*if(k > 0) {
					cout << "res_val = " << gate->gs.val[j] << " (" << m_vANDGates[k][i] << ")" <<
							", startpos = " << m_vMTStartIdx[k] << ", idx = " << idx << ", len = " << len << endl;
				}*/
				idx += len; //TODO put in for loop

			}
		}

		m_vMTIdx[k] = ceil_divide(m_vMTIdx[k], 8) * 8; //pad mtidx to next byte
		m_vMTStartIdx[k] = m_vMTIdx[k];
	}
}

void BoolSharing::AssignInputShares() {
	GATE* gate;
	for (uint32_t i = 0, j, rcvshareidx = 0, bitstocopy, len; i < m_vInputShareGates.size(); i++) {
		gate = m_pGates + m_vInputShareGates[i];
		InstantiateGate(gate);

		bitstocopy = gate->nvals;
		for (j = 0; j < ceil_divide(gate->nvals, GATE_T_BITS); j++, bitstocopy -= GATE_T_BITS) {
			len = min(bitstocopy, (uint32_t) GATE_T_BITS);
			gate->gs.val[j] = m_vInputShareRcvBuf.Get<UGATE_T>(rcvshareidx, len);
#ifdef DEBUGBOOL
			cout << "assigned value " << gate->gs.val[j] << " to gate " << m_vInputShareGates[i] << " with nvals = " << gate->nvals << " and sharebitlen = " << gate->sharebitlen << endl;
#endif
			rcvshareidx += len;
		}
	}
}

void BoolSharing::AssignOutputShares() {
	GATE* gate;
	for (uint32_t i = 0, j, rcvshareidx = 0, bitstocopy, len, parentid; i < m_vOutputShareGates.size(); i++) {
		gate = m_pGates + m_vOutputShareGates[i];
		parentid = gate->ingates.inputs.parent;
		InstantiateGate(gate);

		bitstocopy = gate->nvals;
		for (j = 0; j < ceil_divide(gate->nvals, GATE_T_BITS); j++, bitstocopy -= GATE_T_BITS) {
			len = min(bitstocopy, (uint32_t) GATE_T_BITS);
			gate->gs.val[j] = m_pGates[parentid].gs.val[j] ^ m_vOutputShareRcvBuf.Get<UGATE_T>(rcvshareidx, len);
#ifdef DEBUGBOOL
			cout << "Outshare: " << (hex) << gate->gs.val[j] << " = " << m_pGates[parentid].gs.val[j] << " ^ " <<
					m_vOutputShareRcvBuf.Get<UGATE_T>(rcvshareidx, len) << (dec) << endl;
#endif
			rcvshareidx += len;
		}
		UsedGate(parentid);
	}
}

void BoolSharing::GetDataToSend(vector<BYTE*>& sendbuf, vector<uint32_t>& sndbytes) {
	//Input shares
	if (m_nInputShareSndSize > 0) {
		sendbuf.push_back(m_vInputShareSndBuf.GetArr());
		sndbytes.push_back(ceil_divide(m_nInputShareSndSize, 8));
	}

	//Output shares
	if (m_nOutputShareSndSize > 0) {
		sendbuf.push_back(m_vOutputShareSndBuf.GetArr());
		sndbytes.push_back(ceil_divide(m_nOutputShareSndSize, 8));
	}

	for (uint32_t i = 0; i < m_nNumANDSizes; i++) {
		uint32_t mtbytelen = ceil_divide((m_vMTIdx[i] - m_vMTStartIdx[i]), 8);
		//Selective openings
		if (mtbytelen > 0) {
			sendbuf.push_back(m_vD_snd[i].GetArr() + ceil_divide(m_vMTStartIdx[i], 8));
			sndbytes.push_back(mtbytelen);
			sendbuf.push_back(m_vE_snd[i].GetArr() + ceil_divide(m_vMTStartIdx[i], 8) * m_vANDs[i].bitlen);
			sndbytes.push_back(mtbytelen * m_vANDs[i].bitlen);
		}
#ifdef DEBUGBOOL
		if(mtbytelen > 0) {
			cout << "Sending " << mtbytelen*8 << " multiplication triples" << endl;
		}
#endif
	}

#ifdef DEBUGBOOL
	if(m_nInputShareSndSize > 0) {
		cout << "Sending " << m_nInputShareSndSize << " Input shares : ";
		m_vInputShareSndBuf.Print(0, m_nInputShareSndSize);
	}
	if(m_nOutputShareSndSize > 0) {
		cout << "Sending " << m_nOutputShareSndSize << " Output shares : ";
		m_vOutputShareSndBuf.Print(0, m_nOutputShareSndSize);
	}
#endif
}

void BoolSharing::GetBuffersToReceive(vector<BYTE*>& rcvbuf, vector<uint32_t>& rcvbytes) {
	//Input shares
	if (m_nInputShareRcvSize > 0) {
		if (m_vInputShareRcvBuf.GetSize() < ceil_divide(m_nInputShareRcvSize, 8))
			m_vInputShareRcvBuf.ResizeinBytes(ceil_divide(m_nInputShareRcvSize, 8));
		rcvbuf.push_back(m_vInputShareRcvBuf.GetArr());
		rcvbytes.push_back(ceil_divide(m_nInputShareRcvSize, 8));
	}

	//Output shares
	if (m_nOutputShareRcvSize > 0) {
		if (m_vOutputShareRcvBuf.GetSize() < ceil_divide(m_nOutputShareRcvSize, 8))
			m_vOutputShareRcvBuf.ResizeinBytes(ceil_divide(m_nOutputShareRcvSize, 8));
		rcvbuf.push_back(m_vOutputShareRcvBuf.GetArr());
		rcvbytes.push_back(ceil_divide(m_nOutputShareRcvSize, 8));
	}

	for (uint32_t i = 0; i < m_nNumANDSizes; i++) {
		uint32_t mtbytelen = ceil_divide((m_vMTIdx[i] - m_vMTStartIdx[i]), 8);
		if (mtbytelen > 0) {
			//Selective openings
			rcvbuf.push_back(m_vD_rcv[i].GetArr() + ceil_divide(m_vMTStartIdx[i], 8));
			rcvbytes.push_back(mtbytelen);
			rcvbuf.push_back(m_vE_rcv[i].GetArr() + ceil_divide(m_vMTStartIdx[i], 8) * m_vANDs[i].bitlen);
			rcvbytes.push_back(mtbytelen * m_vANDs[i].bitlen);
		}
	}
}

inline void BoolSharing::InstantiateGate(GATE* gate) {
	gate->gs.val = (UGATE_T*) calloc((ceil_divide(gate->nvals, GATE_T_BITS)), sizeof(UGATE_T));
	gate->instantiated = true;
}

inline void BoolSharing::UsedGate(uint32_t gateid) {
	//Decrease the number of further uses of the gate
	m_pGates[gateid].nused--;
	//If the gate is needed in another subsequent gate, delete it
	if (!m_pGates[gateid].nused) {
		free(m_pGates[gateid].gs.val);
	}
}

void BoolSharing::EvaluateSIMDGate(uint32_t gateid) {
	GATE* gate = m_pGates + gateid;
	uint32_t vsize = gate->nvals;

	if (gate->type == G_COMBINE) {
#ifdef DEBUGSHARING
		cout << " which is a COMBINE gate" << endl;
#endif
		uint32_t* input = gate->ingates.inputs.parents;
		InstantiateGate(gate);

		for (uint32_t k = 0, bitstocopy = vsize; k < ceil_divide(vsize, GATE_T_BITS); k++, bitstocopy -= GATE_T_BITS) {
			uint32_t size = min(bitstocopy, ((uint32_t) GATE_T_BITS));
			gate->gs.val[k] = 0;
			//TODO: not working if valsize of the original gate is greater than GATE_T_BITS!, replace for variable sized function
			for (uint32_t i = 0; i < size; i++) {
				gate->gs.val[k] |= m_pGates[input[i + k * GATE_T_BITS]].gs.val[0] << i;
				UsedGate(input[i + k * GATE_T_BITS]);
			}
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
			gate->gs.val[i / GATE_T_BITS] = (m_pGates[idparent].gs.val[(pos + i) / GATE_T_BITS] >> ((pos + i) % GATE_T_BITS)) & 0x1;
		}
		UsedGate(idparent);
	} else if (gate->type == G_REPEAT) //TODO only meant for single bit values, update
			{
#ifdef DEBUGSHARING
		cout << " which is a REPEATER gate" << endl;
#endif
		uint32_t idparent = gate->ingates.inputs.parent;
		InstantiateGate(gate);

		BYTE byte_val = m_pGates[idparent].gs.val[0] ? MAX_BYTE : ZERO_BYTE;
		memset(gate->gs.val, byte_val, sizeof(UGATE_T) * ceil_divide(vsize, GATE_T_BITS));
		UsedGate(idparent);
	} else if (gate->type == G_PERM) {
#ifdef DEBUGSHARING
		cout << " which is a PERMUTATION gate" << endl;
#endif
		uint32_t* perm = gate->ingates.inputs.parents;
		uint32_t* pos = gate->gs.perm.posids;

		InstantiateGate(gate);

		//TODO: there might be a problem here since some bits might not be set to zero
		memset(gate->gs.val, 0x00, ceil_divide(vsize, 8));

		//TODO: Optimize
		for (uint32_t i = 0; i < vsize; i++) {
			gate->gs.val[i / GATE_T_BITS] |= (((m_pGates[perm[i]].gs.val[pos[i] / GATE_T_BITS] >> (pos[i] % GATE_T_BITS)) & 0x1) << (i % GATE_T_BITS));
			UsedGate(perm[i]);
		}
		free(perm);
		free(pos);
	} else if (gate->type == G_COMBINEPOS) {
#ifdef DEBUGSHARING
		cout << " which is a COMBINEPOS gate" << endl;
#endif
		uint32_t* combinepos = gate->ingates.inputs.parents; //gate->gs.combinepos.input;
		uint32_t arraypos = gate->gs.combinepos.pos / GATE_T_BITS;
		uint32_t bitpos = gate->gs.combinepos.pos % GATE_T_BITS;
		InstantiateGate(gate);
		//TODO: there might be a problem here since some bits might not be set to zero
		memset(gate->gs.val, 0x00, ceil_divide(vsize, 8));
		//TODO: Optimize
		for (uint32_t i = 0; i < vsize; i++) {
			uint32_t idparent = combinepos[i];
			gate->gs.val[i / GATE_T_BITS] |= (((m_pGates[idparent].gs.val[arraypos] >> bitpos) & 0x1) << (i % GATE_T_BITS));
			UsedGate(idparent);
		}
		free(combinepos);
	} else if (gate->type == G_SUBSET) {
#ifdef DEBUGSHARING
		cout << " which is a Subset gate" << endl;
#endif
		uint32_t idparent = gate->ingates.inputs.parent;
		uint32_t* positions = gate->gs.sub_pos.posids; //gate->gs.combinepos.input;
		uint32_t arraypos;
		uint32_t bitpos;
		InstantiateGate(gate);
		memset(gate->gs.val, 0x00, ceil_divide(vsize, 8));

		for (uint32_t i = 0; i < vsize; i++) {
			arraypos = positions[i] / GATE_T_BITS;
			bitpos = positions[i] % GATE_T_BITS;
			gate->gs.val[i / GATE_T_BITS] |= (((m_pGates[idparent].gs.val[arraypos] >> bitpos) & 0x1) << (i % GATE_T_BITS));
		}
		UsedGate(idparent);
		free(positions);
	}
}

uint32_t BoolSharing::AssignInput(CBitVector& inputvals) {
	deque<uint32_t> myingates = m_cBoolCircuit->GetInputGatesForParty(m_eRole);
	inputvals.Create((uint64_t) m_cBoolCircuit->GetNumInputBitsForParty(m_eRole), m_cCrypto);

	GATE* gate;
	uint32_t inbits = 0;
	for (uint32_t i = 0, inbitstart = 0, bitstocopy, len, lim; i < myingates.size(); i++) {
		gate = m_pGates + myingates[i];
		if (!gate->instantiated) {
			bitstocopy = gate->nvals * gate->sharebitlen;
			inbits += bitstocopy;
			lim = ceil_divide(bitstocopy, GATE_T_BITS);

			UGATE_T* inval = (UGATE_T*) calloc(lim, sizeof(UGATE_T));

			for (uint32_t j = 0; j < lim; j++, bitstocopy -= GATE_T_BITS) {
				len = min(bitstocopy, (uint32_t) GATE_T_BITS);
				inval[j] = inputvals.Get<UGATE_T>(inbitstart, len);
				inbitstart += len;
			}
			gate->gs.ishare.inval = inval;
		}
	}
	return inbits;
}

uint32_t BoolSharing::GetOutput(CBitVector& out) {
	deque<uint32_t> myoutgates = m_cBoolCircuit->GetOutputGatesForParty(m_eRole);
	uint32_t outbits = m_cBoolCircuit->GetNumOutputBitsForParty(m_eRole);
	out.Create(outbits);

	GATE* gate;
	for (uint32_t i = 0, outbitstart = 0, bitstocopy, len, lim; i < myoutgates.size(); i++) {
		gate = m_pGates + myoutgates[i];
		lim = gate->nvals * gate->sharebitlen;

		for (uint32_t j = 0; j < lim; j++, outbitstart++) {
			out.SetBitNoMask(outbitstart, (gate->gs.val[j / GATE_T_BITS] >> (j % GATE_T_BITS)) & 0x01);
		}
	}
	return outbits;
}

void BoolSharing::PrintPerformanceStatistics() {
	cout << "Boolean Sharing: ANDs: ";
	for (uint32_t i = 0; i < m_nNumANDSizes; i++)
		cout << m_vANDs[i].numgates << " (" << m_vANDs[i].bitlen << "-bit) ; ";
	cout << "Depth: " << GetMaxCommunicationRounds() << endl;
}

void BoolSharing::Reset() {
	m_nTotalNumMTs = 0;
	m_nXORGates = 0;

	m_nNumANDSizes = 0;

	for (uint32_t i = 0; i < m_nNumMTs.size(); i++) {
		m_nNumMTs[i] = 0;
	}
	for (uint32_t i = 0; i < m_vMTStartIdx.size(); i++)
		m_vMTStartIdx[i] = 0;
	for (uint32_t i = 0; i < m_vMTIdx.size(); i++)
		m_vMTIdx[i] = 0;
	for (uint32_t i = 0; i < m_vANDGates.size(); i++)
		m_vANDGates.clear();
	m_vANDGates.clear();

	m_vInputShareGates.clear();
	m_vOutputShareGates.clear();

	m_nInputShareSndSize = 0;
	m_nOutputShareSndSize = 0;

	m_nInputShareRcvSize = 0;
	m_nOutputShareRcvSize = 0;

	for (uint32_t i = 0; i < m_vA.size(); i++) {
		m_vA[i].delCBitVector();
		m_vB[i].delCBitVector();
		m_vC[i].delCBitVector();
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

	m_cBoolCircuit->Reset();
}
