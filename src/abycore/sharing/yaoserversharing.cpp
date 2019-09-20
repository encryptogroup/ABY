/**
 \file 		yaoserversharing.cpp
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
 \brief		Yao Server Sharing class implementation.
 */

#include "yaoserversharing.h"
#include "../aby/abysetup.h"
#include <cstdlib>

void YaoServerSharing::InitServer() {

	//Allocate memory that is needed when generating the garbled tables
	for(uint32_t i = 0; i < 2; i++) {
		m_bLMaskBuf[i] = (BYTE*) malloc(sizeof(BYTE) * m_nSecParamBytes);
		m_bRMaskBuf[i] = (BYTE*) malloc(sizeof(BYTE) * m_nSecParamBytes);
		m_bOKeyBuf[i] = (BYTE*) malloc(sizeof(BYTE) * m_nSecParamBytes);
	}
	m_bLKeyBuf = (BYTE*) malloc(sizeof(BYTE) * m_nSecParamBytes);
	m_bTmpBuf = (BYTE*) malloc(sizeof(BYTE) * AES_BYTES);

	m_vOutputDestionations = nullptr;

	m_nUniversalGateTableCtr = 0;
	m_nGarbledTableCtr = 0L;
	m_nGarbledTableSndCtr = 0L;

	m_nClientInputKexIdx = 0;
	m_nClientInputKeyCtr = 0;

	m_nOutputShareSndSize = 0;
	m_nOutputShareRcvCtr = 0;

	m_nPermBitCtr = 0;

	fMaskFct = new XORMasking(m_cCrypto->get_seclvl().symbits);

	InitNewLayer();
}

YaoServerSharing::~YaoServerSharing() {
		Reset();
		for(size_t i = 0; i < 2; i++) {
			free(m_bLMaskBuf[i]);
			free(m_bRMaskBuf[i]);
			free(m_bOKeyBuf[i]);
		}
		free(m_bLKeyBuf);
		free(m_bTmpBuf);
		delete fMaskFct;
}

//Pre-set values for new layer
void YaoServerSharing::InitNewLayer() {
	m_nServerKeyCtr = 0;
	m_nClientInBitCtr = 0;
}

/* Send a new task for pre-computing the OTs in the setup phase */
void YaoServerSharing::PrepareSetupPhase(ABYSetup* setup) {
	BYTE* buf;
	uint64_t gt_size;
	uint64_t univ_size;
	uint32_t symbits = m_cCrypto->get_seclvl().symbits;
	m_nANDGates = m_cBoolCircuit->GetNumANDGates();
	m_nUNIVGates = m_cBoolCircuit->GetNumUNIVGates();

	gt_size = ((uint64_t) m_nANDGates) * KEYS_PER_GATE_IN_TABLE * m_nSecParamBytes;
	univ_size = ((uint64_t) m_nUNIVGates) * KEYS_PER_UNIV_GATE_IN_TABLE * m_nSecParamBytes;

	/* If no gates were built, return */
	if (m_cBoolCircuit->GetMaxDepth() == 0)
		return;

	/* Preset the number of input bits for client and server */
	m_nServerInputBits = m_cBoolCircuit->GetNumInputBitsForParty(SERVER);
	m_nClientInputBits = m_cBoolCircuit->GetNumInputBitsForParty(CLIENT);
	m_nConversionInputBits = m_cBoolCircuit->GetNumB2YGates() + m_cBoolCircuit->GetNumA2YGates() + m_cBoolCircuit->GetNumYSwitchGates();

	//m_vPreSetInputGates = (input_gate_val_t*) calloc(m_nServerInputBits, sizeof(input_gate_val_t));

	buf = (BYTE*) malloc(gt_size);
	m_vGarbledCircuit.AttachBuf(buf, gt_size);

	m_vUniversalGateTable.Create(0);
	buf = (BYTE*) malloc(univ_size);
	m_vUniversalGateTable.AttachBuf(buf, univ_size);

	m_vR.Create(symbits, m_cCrypto);
	m_vR.SetBit(symbits - 1, 1);

#ifdef DEBUGYAOSERVER
	std::cout << "Secret key generated: ";
	PrintKey(m_vR.GetArr());
	std::cout << std::endl;
#endif

	m_vROTMasks.resize(2);
	m_vROTMasks[0].Create((m_nClientInputBits + m_nConversionInputBits) * symbits);
	m_vROTMasks[1].Create((m_nClientInputBits + m_nConversionInputBits) * symbits);

	CreateRandomWireKeys(m_vServerInputKeys, m_nServerInputBits + m_cBoolCircuit->GetNumA2YGates());
	CreateRandomWireKeys(m_vClientInputKeys, m_nClientInputBits + m_nConversionInputBits);
	//CreateRandomWireKeys(m_vConversionInputKeys, m_nConversionInputBits);

#ifdef DEBUGYAOSERVER
	std::cout << "Server input keys: ";
	m_vServerInputKeys.PrintHex();
	std::cout << "Client input keys: ";
	m_vClientInputKeys.PrintHex();
#endif

	m_vPermBits.Create(m_nServerInputBits + m_nConversionInputBits, m_cCrypto);

	m_vServerKeySndBuf.Create((m_nServerInputBits + m_cBoolCircuit->GetNumA2YGates()) * symbits);

	m_vClientKeySndBuf.resize(2);
	m_vClientKeySndBuf[0].Create((m_nClientInputBits + m_nConversionInputBits) * symbits);
	m_vClientKeySndBuf[1].Create((m_nClientInputBits + m_nConversionInputBits) * symbits);

	m_vOutputShareSndBuf.Create(m_cBoolCircuit->GetNumOutputBitsForParty(CLIENT));

	m_vOutputDestionations = (e_role*) malloc(
			sizeof(e_role) * (m_cBoolCircuit->GetOutputGatesForParty(CLIENT).size()
					+ m_cBoolCircuit->GetOutputGatesForParty(SERVER).size()));
	m_nOutputDestionationsCtr = 0;
	//std::deque<uint32_t> out = m_cBoolCircuit->GetOutputGatesForParty(CLIENT);

	IKNP_OTTask* task = (IKNP_OTTask*) malloc(sizeof(IKNP_OTTask));
	task->bitlen = symbits;
	task->snd_flavor = Snd_R_OT;
	task->rec_flavor = Rec_OT;
	task->numOTs = m_nClientInputBits + m_nConversionInputBits;
	task->mskfct = fMaskFct;
	task->delete_mskfct = FALSE; // is deleted in destructor
	task->pval.sndval.X0 = &(m_vROTMasks[0]);
	task->pval.sndval.X1 = &(m_vROTMasks[1]);

	setup->AddOTTask(task, m_eContext == S_YAO? 0 : 1);
}

/*  send the garbled table */
void YaoServerSharing::PerformSetupPhase(ABYSetup* setup) {
	/* If no gates were built, return */
	if (m_cBoolCircuit->GetMaxDepth() == 0)
		return;

	CreateAndSendGarbledCircuit(setup);
}

void YaoServerSharing::FinishSetupPhase(ABYSetup* setup) {
	/* If no gates were built, return */

	m_nOutputDestionationsCtr = 0;
	if (m_cBoolCircuit->GetMaxDepth() == 0)
		return;

	setup->WaitForTransmissionEnd();

	//Reset input gates since they were instantiated before
	//TODO: Change execution
	std::deque<uint32_t> insrvgates = m_cBoolCircuit->GetInputGatesForParty(SERVER);
	for (uint32_t i = 0; i < insrvgates.size(); i++) {
		m_vGates[insrvgates[i]].gs.ishare.src = SERVER;
	}

	//Set pre-initialized input values that were instantiated before the setup phase
	for (uint32_t i = 0; i < m_vPreSetInputGates.size(); i++) {
		m_vGates[m_vPreSetInputGates[i].gateid].gs.ishare.inval = m_vPreSetInputGates[i].inval;
	}
	m_vPreSetInputGates.clear();

	//Set pre-initialized input values that were instantiated before the setup phase
	for (uint32_t i = 0; i < m_vPreSetA2YPositions.size(); i++) {
		m_vGates[m_vPreSetA2YPositions[i].gateid].gs.pos = m_vPreSetA2YPositions[i].pos;
	}
	m_vPreSetA2YPositions.clear();

	std::deque<uint32_t> incligates = m_cBoolCircuit->GetInputGatesForParty(CLIENT);
	for (uint32_t i = 0; i < incligates.size(); i++) {
		m_vGates[incligates[i]].gs.ishare.src = CLIENT;
	}



#ifdef DEBUGYAOSERVER
	std::cout << "Resulting X0 from OT: ";
	m_vROTMasks[0].PrintHex();
	std::cout << "Resulting X1 from OT: ";
	m_vROTMasks[1].PrintHex();
#endif
}
void YaoServerSharing::EvaluateLocalOperations(uint32_t depth) {
	//only evalute the PRINT_VAL operation for debugging, all other work was pre-computed
	std::deque<uint32_t> localqueue = m_cBoolCircuit->GetLocalQueueOnLvl(depth);
	GATE* gate;
	for (uint32_t i = 0; i < localqueue.size(); i++) {
		gate = &(m_vGates[localqueue[i]]);
		if(gate->type == G_PRINT_VAL) {
			EvaluatePrintValGate(localqueue[i], C_BOOLEAN);
		} else if(gate->type == G_ASSERT) {
			EvaluateAssertGate(localqueue[i], C_BOOLEAN);
		} else {
			//do nothing
		}
	}
}

void YaoServerSharing::EvaluateInteractiveOperations(uint32_t depth) {
	std::deque<uint32_t> interactivequeue = m_cBoolCircuit->GetInteractiveQueueOnLvl(depth);
	GATE *gate, *parent;

	for (uint32_t i = 0; i < interactivequeue.size(); i++) {
		gate = &(m_vGates[interactivequeue[i]]);
#ifdef DEBUGYAOSERVER
		std::cout << "Evaluating gate with id = " << interactivequeue[i] << ", and type = "<< get_gate_type_name(gate->type) << ", and depth = " << gate->depth << std::endl;
#endif
		switch (gate->type) {
		case G_IN:
			if (gate->gs.ishare.src == SERVER) {
				SendServerInputKey(interactivequeue[i]);
			} else {
				SendClientInputKey(interactivequeue[i]);
			}
			break;
		case G_OUT:
			if (m_vOutputDestionations[m_nOutputDestionationsCtr] == SERVER ||
					m_vOutputDestionations[m_nOutputDestionationsCtr] == ALL) {
				m_vServerOutputGates.push_back(gate);
				m_nOutputShareRcvCtr += gate->nvals;
			}
			m_nOutputDestionationsCtr++;
			//else do nothing since the client has already been given the output
			break;
		case G_CONV:
			parent = &(m_vGates[gate->ingates.inputs.parents[0]]);
			if (parent->context == S_ARITH) {
				SendConversionValues(interactivequeue[i]);
			} else if(parent->context == S_BOOL || parent->context == S_YAO || parent->context == S_YAO_REV) {
				EvaluateConversionGate(interactivequeue[i]);
			}
			break;
		case G_CALLBACK:
			EvaluateCallbackGate(interactivequeue[i]);
			break;
		default:
			std::cerr << "Interactive Operation not recognized: " << (uint32_t) gate->type << " (" << get_gate_type_name(gate->type) << "), stopping execution" << std::endl;
			std::exit(EXIT_FAILURE);
		}

	}
}

void YaoServerSharing::SendConversionValues(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	GATE* parent = &(m_vGates[gate->ingates.inputs.parents[0]]);

	uint32_t pos = gate->gs.pos;
	uint32_t id = pos >> 1;

#ifdef DEBUGYAOSERVER
	std::cout << "Evaluating A2Y with gateid = " << gateid << ", parent = " <<
			gate->ingates.inputs.parents[0] << ", pos = " << pos;
#endif
	assert(parent->instantiated);

	//Convert server's share
	if ((pos & 0x01) == 0) {
		gate->gs.ishare.inval = (UGATE_T*) calloc(ceil_divide(gate->nvals, GATE_T_BITS), sizeof(UGATE_T));
		for(uint32_t i = 0; i < gate->nvals; i++) {
			//gate->gs.ishare.inval[0] = (parent->gs.aval[id / GATE_T_BITS] >> (id % GATE_T_BITS)) & 0x01;
			gate->gs.ishare.inval[i/GATE_T_BITS] |= ((parent->gs.aval[(id+(i*parent->sharebitlen)) / GATE_T_BITS] >>
					((id+i*parent->sharebitlen) % GATE_T_BITS)) & 0x01) << (i% GATE_T_BITS);
		}
#ifdef DEBUGYAOSERVER
		std::cout << " (server share) with value " << (uint32_t) gate->gs.ishare.inval[0] << " (" << id / GATE_T_BITS << ", " << (id%GATE_T_BITS) <<
		", " << parent->gs.aval[0] <<") " << gate->ingates.inputs.parents[0] << ", " << (uint64_t) parent->gs.aval << std::endl;
#endif
		SendServerInputKey(gateid);
	} else { //Convert client's share
#ifdef DEBUGYAOSERVER
	std::cout << " (client share) " << std::endl;
#endif
		m_nClientInBitCtr += gate->nvals;
		m_vClientInputGate.push_back(gateid);
	}
}

void YaoServerSharing::SendServerInputKey(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	UGATE_T* input = gate->gs.ishare.inval;

	for (uint32_t i = 0; i < gate->nvals; i++, m_nServerKeyCtr++, m_nPermBitCtr++) {
		if (!!((input[i / GATE_T_BITS] >> (i % GATE_T_BITS)) & 0x01) ^ m_vPermBits.GetBit(m_nPermBitCtr)) {
			m_pKeyOps->XOR(m_bTempKeyBuf, m_vServerInputKeys.GetArr() + m_nPermBitCtr * m_nSecParamBytes, m_vR.GetArr());
			memcpy(m_vServerKeySndBuf.GetArr() + m_nServerKeyCtr * m_nSecParamBytes, m_bTempKeyBuf, m_nSecParamBytes);
		} else {
			//input bit at position is 0 -> set 0 key
			memcpy(m_vServerKeySndBuf.GetArr() + m_nServerKeyCtr * m_nSecParamBytes, m_vServerInputKeys.GetArr() + m_nPermBitCtr * m_nSecParamBytes, m_nSecParamBytes);
		}
	}
	free(input);
}

void YaoServerSharing::SendClientInputKey(uint32_t gateid) {
	//push back and wait for bit of client
	GATE* gate = &(m_vGates[gateid]);
	m_nClientInBitCtr += gate->nvals;
	m_vClientInputGate.push_back(gateid);
}

void YaoServerSharing::PrepareOnlinePhase() {
	//Do nothing right now, figure out which parts come here
	m_nClientInBitCtr = 0;
	m_nPermBitCtr = 0;
}

void YaoServerSharing::CreateAndSendGarbledCircuit(ABYSetup* setup) {
	//Go over all gates and garble them

	uint32_t maxdepth = m_cBoolCircuit->GetMaxDepth();
	if (maxdepth == 0)
		return;

	for (uint32_t i = 0; i < maxdepth; i++) {
		std::deque<uint32_t> localqueue = m_cBoolCircuit->GetLocalQueueOnLvl(i);
		PrecomputeGC(localqueue, setup);
		std::deque<uint32_t> interactivequeue = m_cBoolCircuit->GetInteractiveQueueOnLvl(i);
		PrecomputeGC(interactivequeue, setup);
	}
	//Store the shares of the clients output gates
	CollectClientOutputShares();

	//Send the garbled circuit and the output mapping to the client
	if (m_nANDGates > 0 && m_nGarbledTableSndCtr < m_nGarbledTableCtr) {
		setup->AddSendTask(m_vGarbledCircuit.GetArr() + m_nGarbledTableSndCtr * m_nSecParamBytes * KEYS_PER_GATE_IN_TABLE,
				(m_nGarbledTableCtr - m_nGarbledTableSndCtr) * m_nSecParamBytes * KEYS_PER_GATE_IN_TABLE);
		m_nGarbledTableSndCtr = m_nGarbledTableCtr;
	}
	if (m_nUNIVGates > 0)
		setup->AddSendTask(m_vUniversalGateTable.GetArr(), m_nUNIVGates * m_nSecParamBytes * KEYS_PER_UNIV_GATE_IN_TABLE);
	if (m_cBoolCircuit->GetNumOutputBitsForParty(CLIENT) > 0) {
		setup->AddSendTask(m_vOutputShareSndBuf.GetArr(), ceil_divide(m_cBoolCircuit->GetNumOutputBitsForParty(CLIENT), 8));
	}
#ifdef DEBUGYAOSERVER
	std::cout << "Sending Garbled Circuit: ";
	m_vGarbledCircuit.PrintHex();
	std::cout << "Sending my output shares: ";
	m_vOutputShareSndBuf.Print(0, m_cBoolCircuit->GetNumOutputBitsForParty(CLIENT));
#endif

}

void YaoServerSharing::PrecomputeGC(std::deque<uint32_t>& queue, ABYSetup* setup) {
	for (uint32_t i = 0; i < queue.size(); i++) {
		GATE* gate = &(m_vGates[queue[i]]);
#ifdef DEBUGYAOSERVER
		std::cout << "Evaluating gate with id = " << queue[i] << ", and type = "<< get_gate_type_name(gate->type) << "(" << gate->type << "), depth = " << gate->depth
		<< ", nvals = " << gate->nvals << ", sharebitlen = " << gate->sharebitlen << std::endl;
#endif
		assert(gate->nvals > 0 && gate->sharebitlen == 1);

		if (gate->type == G_LIN) {
			EvaluateXORGate(gate);
		} else if (gate->type == G_NON_LIN) {
			EvaluateANDGate(gate, setup);
		} else if (gate->type == G_IN) {
			EvaluateInputGate(queue[i]);
		} else if (gate->type == G_OUT) {
#ifdef DEBUGYAOSERVER
			std::cout << "Obtained output gate with key = ";
			uint32_t parentid = gate->ingates.inputs.parent;
			PrintKey(m_vGates[parentid].gs.yinput.outKey);
			std::cout << " and pi = " << (uint32_t) m_vGates[parentid].gs.yinput.pi[0] << std::endl;
#endif
			EvaluateOutputGate(gate);
		} else if (gate->type == G_CONV) {
#ifdef DEBUGYAOSERVER
			std::cout << "Ealuating conversion gate" << std::endl;
#endif
			EvaluateConversionGate(queue[i]);
		} else if (gate->type == G_CONSTANT) {
			EvaluateConstantGate(gate);
#ifdef DEBUGYAOSERVER
			std::cout << "Assigned key to constant gate " << queue[i] << " (" << (uint32_t) gate->gs.yinput.pi[0] << ") : ";
			PrintKey(gate->gs.yinput.outKey);
			std::cout << std::endl;
#endif
		} else if (IsSIMDGate(gate->type)) {
			EvaluateSIMDGate(queue[i]);
		} else if (gate->type == G_INV) {
			EvaluateInversionGate(gate);
		} else if (gate->type == G_CALLBACK) {
			EvaluateCallbackGate(queue[i]);
		} else if (gate->type == G_UNIV) {
			EvaluateUniversalGate(gate);
		} else if (gate->type == G_SHARED_OUT) {
			GATE* parent = &(m_vGates[gate->ingates.inputs.parent]);
			InstantiateGate(gate);
			memcpy(gate->gs.yinput.outKey, parent->gs.yinput.outKey, gate->nvals * m_nSecParamBytes);
			memcpy(gate->gs.yinput.pi, parent->gs.yinput.pi, gate->nvals);
			UsedGate(gate->ingates.inputs.parent);
			// TODO this currently copies both keys and bits and getclearvalue will probably fail.
			//std::cerr << "SharedOutGate is not properly tested for Yao!" << std::endl;
		} else if(gate->type == G_SHARED_IN) {
			//Do nothing
		} else if(gate->type == G_PRINT_VAL) {
			//Do nothing since inputs are not known yet and hence no debugging can occur
		} else if(gate->type == G_ASSERT) {
			//Do nothing since inputs are not known yet and hence no debugging can occur
		} else {
			std::cerr << "Operation not recognized: " << (uint32_t) gate->type << "(" << get_gate_type_name(gate->type) << ")" << std::endl;
			std::exit(EXIT_FAILURE);
		}
	}
}

void YaoServerSharing::EvaluateInversionGate(GATE* gate) {
	uint32_t parentid = gate->ingates.inputs.parent;
	InstantiateGate(gate);
	assert((gate - m_vGates.data()) > parentid);
	memcpy(gate->gs.yinput.outKey, m_vGates[parentid].gs.yinput.outKey, m_nSecParamBytes * gate->nvals);
	for (uint32_t i = 0; i < gate->nvals; i++) {
		gate->gs.yinput.pi[i] = m_vGates[parentid].gs.yinput.pi[i] ^ 0x01;

		assert(gate->gs.yinput.pi[i] < 2 && m_vGates[parentid].gs.yinput.pi[i] < 2);

	}
	UsedGate(parentid);
}

void YaoServerSharing::EvaluateInputGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	if (gate->gs.ishare.src == SERVER) {

		if(gate->instantiated) {
			input_gate_val_t ingatevals;
			ingatevals.gateid = gateid;
			ingatevals.inval = gate->gs.ishare.inval;
			m_vPreSetInputGates.push_back(ingatevals);
		}
		InstantiateGate(gate);

		memcpy(gate->gs.yinput.outKey, m_vServerInputKeys.GetArr() + m_nPermBitCtr * m_nSecParamBytes, m_nSecParamBytes * gate->nvals);
		for (uint32_t i = 0; i < gate->nvals; i++) {
			gate->gs.yinput.pi[i] = m_vPermBits.GetBit(m_nPermBitCtr);
			m_nPermBitCtr++;
		}
	} else {
		InstantiateGate(gate);

		memcpy(gate->gs.yinput.outKey, m_vClientInputKeys.GetArr() + m_nClientInBitCtr * m_nSecParamBytes, m_nSecParamBytes * gate->nvals);
		memset(gate->gs.yinput.pi, 0, gate->nvals);
		m_nClientInBitCtr += gate->nvals;
		m_vClientInputGate.push_back(gateid);
	}
#ifdef DEBUGYAOSERVER
	std::cout << "Assigned key to input gate " << gateid << " (" << (uint32_t) gate->gs.yinput.pi[0] << ") : ";
	PrintKey(gate->gs.yinput.outKey);
	std::cout << std::endl;
#endif
}

/* Treat conversion gates as a combination of server and client inputs - set permutation bit
 * and perform an oblivious transfer
 */
void YaoServerSharing::EvaluateConversionGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	GATE* parent = &(m_vGates[gate->ingates.inputs.parents[0]]);
	uint32_t pos = gate->gs.pos;
	InstantiateGate(gate);

	if (parent->context == S_BOOL) {
		memcpy(gate->gs.yinput.outKey, m_vClientInputKeys.GetArr() + m_nClientInBitCtr * m_nSecParamBytes, m_nSecParamBytes * gate->nvals);
		for (uint32_t i = 0; i < gate->nvals; i++) {
			gate->gs.yinput.pi[i] = m_vPermBits.GetBit(m_nPermBitCtr);
			m_nPermBitCtr++;
		}

		m_nClientInBitCtr += gate->nvals;
		m_vClientInputGate.push_back(gateid);
	} else if(parent->context == S_YAO || parent->context == S_YAO_REV) {//TODO: merge with S_BOOL routine
		//std::cout << "Performing transform roles protocol!" << std::endl;
		memcpy(gate->gs.yinput.outKey, m_vClientInputKeys.GetArr() + m_nClientInBitCtr * m_nSecParamBytes, m_nSecParamBytes * gate->nvals);
		for (uint32_t i = 0; i < gate->nvals; i++) {
			gate->gs.yinput.pi[i] = m_vPermBits.GetBit(m_nPermBitCtr);
			m_nPermBitCtr++;
		}

		m_nClientInBitCtr += gate->nvals;
		m_vClientInputGate.push_back(gateid);

		//std::cout << "done" << std::endl;
	} else if (parent->context == S_ARITH) {
#ifdef DEBUGYAOSERVER
		std::cout << "Evaluating arithmetic conversion gate with gateid = " << gateid << " and pos = " << pos;
#endif
		//Convert server's share
		a2y_gate_pos_t a2ygate;
		a2ygate.gateid = gateid;
		a2ygate.pos = pos;
		m_vPreSetA2YPositions.push_back(a2ygate);
		if((pos & 0x01) == 0) {
#ifdef DEBUGYAOSERVER
			std::cout << " converting server share" << std::endl;
#endif
			memcpy(gate->gs.yinput.outKey, m_vServerInputKeys.GetArr() + m_nPermBitCtr * m_nSecParamBytes, m_nSecParamBytes * gate->nvals);
			for (uint32_t i = 0; i < gate->nvals; i++) {
				gate->gs.yinput.pi[i] = m_vPermBits.GetBit(m_nPermBitCtr);
				m_nPermBitCtr++;
			}
		} else { //Convert client's share
#ifdef DEBUGYAOSERVER
		std::cout << " converting client share" << std::endl;
#endif
			memcpy(gate->gs.yinput.outKey, m_vClientInputKeys.GetArr() + m_nClientInBitCtr * m_nSecParamBytes, m_nSecParamBytes * gate->nvals);
			memset(gate->gs.yinput.pi, 0, gate->nvals);
			//gate->gs.yinput.pi[0] = 0;
			m_nClientInBitCtr += gate->nvals;
			m_vClientInputGate.push_back(gateid);
		}
	}
#ifdef DEBUGYAOSERVER
	std::cout << "Assigned key to conversion gate " << gateid << " (" << (uint32_t) gate->gs.yinput.pi[0] << ") : ";
	PrintKey(gate->gs.yinput.outKey);
	std::cout << std::endl;
#endif
	// not calling UsedGate(gate->ingates.inputs.parents[0]) here:
	// is called in YaoServerSharing::FinishCircuitLayer()
}

//TODO: optimize for uint64_t pointers
void YaoServerSharing::EvaluateXORGate(GATE* gate) {
	uint32_t idleft = gate->ingates.inputs.twin.left; //gate->gs.ginput.left;
	uint32_t idright = gate->ingates.inputs.twin.right; //gate->gs.ginput.right;

	BYTE* lpi = m_vGates[idleft].gs.yinput.pi;
	BYTE* rpi = m_vGates[idright].gs.yinput.pi;

	BYTE* lkey = m_vGates[idleft].gs.yinput.outKey;
	BYTE* rkey = m_vGates[idright].gs.yinput.outKey;
	InstantiateGate(gate);

	BYTE* gpi = gate->gs.yinput.pi;
	BYTE* gkey = gate->gs.yinput.outKey;

#ifdef GATE_INST_FLAG
	assert(m_vGates[idleft].instantiated);
	assert(m_vGates[idright].instantiated);
#endif
	for (uint32_t g = 0; g < gate->nvals; g++, gpi++, lpi++, rpi++, lkey += m_nSecParamBytes, rkey += m_nSecParamBytes, gkey += m_nSecParamBytes) {
		*gpi = *lpi ^ *rpi;
		m_pKeyOps->XOR(gkey, lkey, rkey);
		assert(*gpi < 2);
	}

#ifdef DEBUGYAOSERVER
	PrintKey(gate->gs.yinput.outKey);
	std::cout << " (" << (uint32_t) gate->gs.yinput.pi[0] << ") = ";
	PrintKey(m_vGates[idleft].gs.yinput.outKey);
	std::cout << " (" << (uint32_t) m_vGates[idleft].gs.yinput.pi[0] << ")(" << idleft << ") ^ ";
	PrintKey(m_vGates[idright].gs.yinput.outKey);
	std::cout << " (" << (uint32_t) m_vGates[idright].gs.yinput.pi[0] << ")(" << idright << ")" << std::endl;
#endif

	assert(m_vGates[idleft].gs.yinput.pi[0] < 2 && m_vGates[idright].gs.yinput.pi[0] < 2);
	UsedGate(idleft);
	UsedGate(idright);
}

//Evaluate an AND gate
void YaoServerSharing::EvaluateANDGate(GATE* gate, ABYSetup* setup) {
	uint32_t idleft = gate->ingates.inputs.twin.left;//gate->gs.ginput.left;
	uint32_t idright = gate->ingates.inputs.twin.right;//gate->gs.ginput.right;

	GATE* gleft = &(m_vGates[idleft]);
	GATE* gright = &(m_vGates[idright]);

	InstantiateGate(gate);

	for(uint32_t g = 0; g < gate->nvals; g++) {
		CreateGarbledTable(gate, g, gleft, gright);
		m_nGarbledTableCtr++;
		assert(gate->gs.yinput.pi[g] < 2);

	}

	if((m_nGarbledTableCtr - m_nGarbledTableSndCtr) >= GARBLED_TABLE_WINDOW) {
		//setup->AddSendTask(m_vGarbledCircuit.GetArr(), m_nGarbledTableCtr * m_nSecParamBytes * KEYS_PER_GATE_IN_TABLE);
		setup->AddSendTask(m_vGarbledCircuit.GetArr() + m_nGarbledTableSndCtr * m_nSecParamBytes * KEYS_PER_GATE_IN_TABLE,
				(m_nGarbledTableCtr - m_nGarbledTableSndCtr) * m_nSecParamBytes * KEYS_PER_GATE_IN_TABLE);
		m_nGarbledTableSndCtr = m_nGarbledTableCtr;
	}

	UsedGate(idleft);
	UsedGate(idright);
}


void YaoServerSharing::CreateGarbledTable(GATE* ggate, uint32_t pos, GATE* gleft, GATE* gright){
	uint8_t *table, *lkey, *rkey, *outwire_key;
	uint8_t lpbit = gleft->gs.yinput.pi[pos];
	uint8_t rpbit = gright->gs.yinput.pi[pos];
	uint8_t lsbit, rsbit;

	assert(lpbit < 2 && rpbit < 2);

	table = m_vGarbledCircuit.GetArr() + m_nGarbledTableCtr * KEYS_PER_GATE_IN_TABLE * m_nSecParamBytes;
	outwire_key = ggate->gs.yinput.outKey + pos * m_nSecParamBytes;

	lkey = gleft->gs.yinput.outKey + pos * m_nSecParamBytes;
	rkey = gright->gs.yinput.outKey + pos * m_nSecParamBytes;

	lsbit = (lkey[m_nSecParamBytes-1] & 0x01);
	rsbit = (rkey[m_nSecParamBytes-1] & 0x01);

	if(lpbit) {
		m_pKeyOps->XOR(m_bLKeyBuf, lkey, m_vR.GetArr());
	} else {
		memcpy(m_bLKeyBuf, lkey, m_nSecParamBytes);
	}

	//Encryptions of wire A
	EncryptWire(m_bLMaskBuf[lpbit], lkey, KEYS_PER_GATE_IN_TABLE*m_nGarbledTableCtr);
	m_pKeyOps->XOR(m_bTmpBuf, lkey, m_vR.GetArr());
	EncryptWire(m_bLMaskBuf[!lpbit], m_bTmpBuf, KEYS_PER_GATE_IN_TABLE*m_nGarbledTableCtr);

	//Encryptions of wire B
	EncryptWire(m_bRMaskBuf[rpbit], rkey, KEYS_PER_GATE_IN_TABLE*m_nGarbledTableCtr+1);
	m_pKeyOps->XOR(m_bTmpBuf, rkey, m_vR.GetArr());
	EncryptWire(m_bRMaskBuf[!rpbit], m_bTmpBuf, KEYS_PER_GATE_IN_TABLE*m_nGarbledTableCtr+1);

	//Compute two table entries, T_G is the first cipher-text, T_E the second cipher-text
	//Compute T_G = Enc(W_a^0) XOR Enc(W_a^1) XOR p_b*R

	m_pKeyOps->XOR(table, m_bLMaskBuf[0], m_bLMaskBuf[1]);
	if(rpbit)
		m_pKeyOps->XOR(table, table, m_vR.GetArr());

	if(lpbit)
		m_pKeyOps->XOR(outwire_key, m_bLMaskBuf[1], m_bRMaskBuf[0]);
	else
		m_pKeyOps->XOR(outwire_key, m_bLMaskBuf[0], m_bRMaskBuf[0]);

	if((lsbit) & (rsbit))
		m_pKeyOps->XOR(outwire_key, outwire_key, m_vR.GetArr());


	//Compute W^0 = W_G^0 XOR W_E^0 = Enc(W_a^0) XOR Enc(W_b^0) XOR p_a*T_G XOR p_b * (T_E XOR W_a^0)

	//Compute T_E = Enc(W_b^0) XOR Enc(W_b^1) XOR W_a^0
	m_pKeyOps->XOR(table + m_nSecParamBytes, m_bRMaskBuf[0], m_bRMaskBuf[1]);
	m_pKeyOps->XOR(table + m_nSecParamBytes, table + m_nSecParamBytes, m_bLKeyBuf);

	//Compute the resulting key for the output wire
	if(rpbit) {
		//std::cout << "Server Xoring right_table" << std::endl;
		m_pKeyOps->XOR(outwire_key, outwire_key, table + m_nSecParamBytes);
		m_pKeyOps->XOR(outwire_key, outwire_key, m_bLKeyBuf);
	}

	//Set permutation bit
	if((outwire_key[m_nSecParamBytes-1] & 0x01)) {
		m_pKeyOps->XOR(outwire_key, outwire_key, m_vR.GetArr());
		ggate->gs.yinput.pi[pos] = !(outwire_key[m_nSecParamBytes-1] & 0x01) ^ ((lpbit) & (rpbit));
	} else {
		ggate->gs.yinput.pi[pos] = (outwire_key[m_nSecParamBytes-1] & 0x01) ^ ((lpbit) & (rpbit));
	}

#ifdef DEBUGYAOSERVER
		std::cout << " encr : ";
		PrintKey(lkey);
		std::cout << " (" << (uint32_t) gleft->gs.yinput.pi[pos] << ") and : ";
		PrintKey(rkey);
		std::cout << " (" << (uint32_t) gright->gs.yinput.pi[pos] << ") to : ";
		PrintKey(outwire_key);
		std::cout << " (" << (uint32_t) ggate->gs.yinput.pi[pos] << ")" << std::endl;
		std::cout << "A_0: ";
		PrintKey(m_bLMaskBuf[0]);
		std::cout << "; A_1: ";
		PrintKey(m_bLMaskBuf[1]);
		std::cout << std::endl << "B_0: ";
		PrintKey(m_bRMaskBuf[0]);
		std::cout << "; B_1: ";
		PrintKey(m_bRMaskBuf[1]);

		std::cout << std::endl << "Table A: ";
		PrintKey(table);
		std::cout << "; Table B: ";
		PrintKey(table+m_nSecParamBytes);
		std::cout << std::endl;

#endif
}

//Evaluate a Universal Gate
void YaoServerSharing::EvaluateUniversalGate(GATE* gate) {
	uint32_t idleft = gate->ingates.inputs.twin.left;
	uint32_t idright = gate->ingates.inputs.twin.right;

	GATE* gleft = &(m_vGates[idleft]);
	GATE* gright = &(m_vGates[idright]);
	uint32_t ttable = gate->gs.ttable;

	InstantiateGate(gate);

	for(uint32_t g = 0; g < gate->nvals; g++) {
		GarbleUniversalGate(gate, g, gleft, gright, ttable);
		m_nUniversalGateTableCtr++;
		//gate->gs.yinput.pi[g] = 0;
		assert(gate->gs.yinput.pi[g] < 2);
	}
	UsedGate(idleft);
	UsedGate(idright);
}

//Garble a universal gate via the GRR-3 optimization
void YaoServerSharing::GarbleUniversalGate(GATE* ggate, uint32_t pos, GATE* gleft, GATE* gright, uint32_t ttable) {
	BYTE* univ_table = m_vUniversalGateTable.GetArr() + m_nUniversalGateTableCtr * KEYS_PER_UNIV_GATE_IN_TABLE * m_nSecParamBytes;
	uint32_t ttid = (gleft->gs.yinput.pi[pos] << 1) + gright->gs.yinput.pi[pos];

	assert(gright->instantiated && gleft->instantiated);

	memcpy(m_bLMaskBuf[0], gleft->gs.yinput.outKey + pos * m_nSecParamBytes, m_nSecParamBytes);
	m_pKeyOps->XOR(m_bLMaskBuf[1], m_bLMaskBuf[0], m_vR.GetArr());

	memcpy(m_bRMaskBuf[0], gright->gs.yinput.outKey + pos * m_nSecParamBytes, m_nSecParamBytes);
	m_pKeyOps->XOR(m_bRMaskBuf[1], m_bRMaskBuf[0], m_vR.GetArr());

	BYTE* outkey[2];
	outkey[0] = ggate->gs.yinput.outKey + pos * m_nSecParamBytes;
	outkey[1] = m_bOKeyBuf[0];

	assert(((uint64_t*) m_bZeroBuf)[0] == 0);
	//GRR: Encryption with both original keys of a zero-string becomes the key on the output wire of the gate
	EncryptWireGRR3(outkey[0], m_bZeroBuf, m_bLMaskBuf[0], m_bRMaskBuf[0], 0);

	//Sort the values according to the permutation bit and precompute the second wire key
	BYTE kbit = outkey[0][m_nSecParamBytes-1] & 0x01;
	ggate->gs.yinput.pi[pos] = ((ttable>>ttid)&0x01) ^ kbit;//((kbit^1) & (ttid == 3)) | (kbit & (ttid != 3));

#ifdef DEBUGYAOSERVER
		std::cout << " encrypting : ";
		PrintKey(m_bZeroBuf);
		std::cout << " using: ";
		PrintKey(m_bLMaskBuf[0]);
		std::cout << " (" << (uint32_t) gleft->gs.yinput.pi[pos] << ") and : ";
		PrintKey(m_bRMaskBuf[0]);
		std::cout << " (" << (uint32_t) gright->gs.yinput.pi[pos] << ") to : ";
		PrintKey(m_bOKeyBuf[0]);
		std::cout << std::endl;
#endif
	memcpy(outkey[kbit], outkey[0], m_nSecParamBytes);
	m_pKeyOps->XOR(outkey[kbit^1], outkey[kbit], m_vR.GetArr());

	for(uint32_t i = 1, keyid; i < 4; i++, univ_table+=m_nSecParamBytes) {
		keyid = ((ttable>>(ttid^i))&0x01) ^ ggate->gs.yinput.pi[pos];
		assert(keyid < 2);
		//cout << "Encrypting into outkey = " << outkey << ", " << (unsigned long) m_bOKeyBuf[0] << ", " <<  (unsigned long) m_bOKeyBuf[1] <<
		//		", truthtable = " << (unsigned uint32_t) g_TruthTable[id^i] << ", mypermbit = " << (unsigned uint32_t) ggate->gs.yinput.pi[pos] << ", id = " << id << endl;
		EncryptWireGRR3(univ_table, outkey[keyid], m_bLMaskBuf[i>>1], m_bRMaskBuf[i&0x01], i);
#ifdef DEBUGYAOSERVER
		std::cout << " encrypting : ";
		PrintKey(m_bOKeyBuf[0]); // TODO: check that we print the right value
		std::cout << " using: ";
		PrintKey(m_bLMaskBuf[i>>1]);
		std::cout << " (" << (uint32_t) gleft->gs.yinput.pi[pos] << ") and : ";
		PrintKey(m_bRMaskBuf[i&0x01]);
		std::cout << " (" << (uint32_t) gright->gs.yinput.pi[pos] << ") to : ";
		PrintKey(univ_table); // TODO: check that we print the right value
		std::cout << std::endl;
#endif
	}
}

//Collect the permutation bits on the clients output gates and prepare them to be sent off
void YaoServerSharing::CollectClientOutputShares() {
	std::deque<uint32_t> out = m_cBoolCircuit->GetOutputGatesForParty(CLIENT);
	while (out.size() > 0) {
		for (uint32_t j = 0; j < m_vGates[out.front()].nvals; j++, m_nOutputShareSndSize++) {
			m_vOutputShareSndBuf.SetBit(m_nOutputShareSndSize, !!((m_vGates[out.front()].gs.val[j / GATE_T_BITS]) & ((UGATE_T) 1 << (j % GATE_T_BITS))));
		}
		out.pop_front();
	}
}

void YaoServerSharing::EvaluateConstantGate(GATE* gate) {
	//assign 0 and 1 gates
	UGATE_T constval = gate->gs.constval;
	InstantiateGate(gate);
	memset(gate->gs.yinput.outKey, 0, m_nSecParamBytes * gate->nvals);
	for (uint32_t i = 0; i < gate->nvals; ++i) {
		if(constval == 1L) {
			gate->gs.yinput.pi[i] = 1;
		} else {
			gate->gs.yinput.pi[i] = 0;
		}
	}
}

void YaoServerSharing::EvaluateOutputGate(GATE* gate) {
	uint32_t parentid = gate->ingates.inputs.parent;

	//push the output back since it will be deleted but is needed in the online phase
	//std::cout << "Before " << std::endl;
	m_vOutputDestionations[m_nOutputDestionationsCtr++] = gate->gs.oshare.dst;

	//std::cout << "After" << std::endl;
	//InstantiateGate(gate);

	gate->gs.val = (UGATE_T*) calloc(ceil_divide(gate->nvals, GATE_T_BITS), sizeof(UGATE_T));
	gate->instantiated = true;
	for (uint32_t i = 0; i < gate->nvals; i++) {
		gate->gs.val[i / GATE_T_BITS] |= (((UGATE_T) m_vGates[parentid].gs.yinput.pi[i]) << (i % GATE_T_BITS));
	}

#ifdef DEBUGYAOSERVER
	std::cout << "Stored output share " << gate->gs.val[0] << std::endl;
#endif
	UsedGate(parentid);
}

void YaoServerSharing::GetDataToSend(std::vector<BYTE*>& sendbuf, std::vector<uint64_t>& sndbytes) {
	//Input keys of server
	if (m_nServerKeyCtr > 0) {
#ifdef DEBUGYAOSERVER
		std::cout << "want to send servers input keys which are of size " << m_nServerKeyCtr * m_nSecParamBytes << " bytes" << std::endl;
		std::cout << "Server input keys = ";
		m_vServerKeySndBuf.PrintHex();
#endif
		sendbuf.push_back(m_vServerKeySndBuf.GetArr());
		sndbytes.push_back(m_nServerKeyCtr * m_nSecParamBytes);
	}
	//Input keys of client
	if (m_nClientInputKeyCtr > 0) {
#ifdef DEBUGYAOSERVER
		std::cout << "want to send client input keys which are of size 2 * " << m_nClientInputKeyCtr * m_nSecParamBytes << " bytes" << std::endl;
		std::cout << "Client input keys[0] = ";
		m_vClientKeySndBuf[0].PrintHex();
		std::cout << "Client input keys[1] = ";
		m_vClientKeySndBuf[1].PrintHex();
#endif
		sendbuf.push_back(m_vClientKeySndBuf[0].GetArr());
		sndbytes.push_back(m_nClientInputKeyCtr * m_nSecParamBytes);
		sendbuf.push_back(m_vClientKeySndBuf[1].GetArr());
		sndbytes.push_back(m_nClientInputKeyCtr * m_nSecParamBytes);
		m_nClientInputKeyCtr = 0;
	}
}

void YaoServerSharing::FinishCircuitLayer() {
	//Use OT bits from the client to determine the send bits that are supposed to go out next round
	if (m_nClientInBitCtr > 0) {
		for (uint32_t i = 0, linbitctr = 0; i < m_vClientInputGate.size() && linbitctr < m_nClientInBitCtr; i++) {
			uint32_t gateid = m_vClientInputGate[i];
			if (m_vGates[gateid].type == G_IN) {
				for (uint32_t k = 0; k < m_vGates[gateid].nvals; k++, linbitctr++, m_nClientInputKexIdx++, m_nClientInputKeyCtr++) {

					m_pKeyOps->XOR(m_bTempKeyBuf, m_vClientInputKeys.GetArr() + m_nClientInputKexIdx * m_nSecParamBytes, m_vR.GetArr());
					if (m_vClientROTRcvBuf.GetBitNoMask(linbitctr) == 1) {
						//Swap masks
						m_pKeyOps->XOR(m_vClientKeySndBuf[0].GetArr() + linbitctr * m_nSecParamBytes, m_vROTMasks[0].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes,
								m_bTempKeyBuf); //One - key
						m_pKeyOps->XOR(m_vClientKeySndBuf[1].GetArr() + linbitctr * m_nSecParamBytes, m_vROTMasks[1].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes,
								m_vClientInputKeys.GetArr() + m_nClientInputKexIdx * m_nSecParamBytes); //Zero - key
#ifdef DEBUGYAOSERVER
										std::cout << "T0: ";
										PrintKey(m_vClientKeySndBuf[0].GetArr() + linbitctr * m_nSecParamBytes);
										std::cout << " = ";
										PrintKey(m_vROTMasks[0].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes);
										std::cout << " ^ ";
										PrintKey(m_bTempKeyBuf);
										std::cout << std::endl;
										std::cout << "T1: ";
										PrintKey(m_vClientKeySndBuf[1].GetArr() + linbitctr * m_nSecParamBytes);
										std::cout << " = ";
										PrintKey(m_vROTMasks[1].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes);
										std::cout << " ^ ";
										PrintKey(m_vClientInputKeys.GetArr() + m_nClientInputKexIdx * m_nSecParamBytes);

										std::cout << std::endl;
#endif
					} else {
						//masks remain the same
						m_pKeyOps->XOR(m_vClientKeySndBuf[0].GetArr() + linbitctr * m_nSecParamBytes, m_vROTMasks[0].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes,
								m_vClientInputKeys.GetArr() + m_nClientInputKexIdx * m_nSecParamBytes); //Zero - key
						m_pKeyOps->XOR(m_vClientKeySndBuf[1].GetArr() + linbitctr * m_nSecParamBytes, m_vROTMasks[1].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes,
								m_bTempKeyBuf); //One - key
#ifdef DEBUGYAOSERVER
								std::cout << "T0: ";
								PrintKey(m_vClientKeySndBuf[0].GetArr() + linbitctr * m_nSecParamBytes);
								std::cout << " = ";
								PrintKey(m_vROTMasks[0].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes);
								std::cout << " ^ ";
								PrintKey(m_vClientInputKeys.GetArr() + m_nClientInputKexIdx * m_nSecParamBytes);
								std::cout << std::endl;
								std::cout << "T1: ";
								PrintKey(m_vClientKeySndBuf[1].GetArr() + linbitctr * m_nSecParamBytes);
								std::cout << " = ";
								PrintKey(m_vROTMasks[1].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes);
								std::cout << " ^ ";
								PrintKey(m_bTempKeyBuf);
								std::cout << std::endl;
#endif
					}
				}
			} else { //Evaluate conversion gates
				uint32_t input = m_vGates[gateid].ingates.inputs.parents[0];

				for (uint32_t k = 0; k < m_vGates[gateid].nvals; k++, linbitctr++, m_nClientInputKexIdx++, m_nClientInputKeyCtr++) {
					m_pKeyOps->XOR(m_bTempKeyBuf, m_vClientInputKeys.GetArr() + m_nClientInputKexIdx * m_nSecParamBytes, m_vR.GetArr());
					uint32_t permval = 0;
					if (m_vGates[input].context == S_BOOL) {
						uint32_t val = (m_vGates[input].gs.val[k / GATE_T_BITS] >> (k % GATE_T_BITS)) & 0x01;
						permval = val ^ m_vGates[gateid].gs.yinput.pi[k];
					} else  if (m_vGates[input].context == S_YAO || m_vGates[input].context == S_YAO_REV) {//switch roles gate
						//std::cout << "copying keys from input " << input << " at position " << k << std::endl;
						assert(m_vGates[input].instantiated);
						uint32_t val = m_vGates[input].gs.yval[((k+1) * m_nSecParamBytes)-1] & 0x01; //get client permutation bit
						//std::cout << "Server conv share = " << val << std::endl;
						permval = val ^ m_vGates[gateid].gs.yinput.pi[k];
						//std::cout << "done copying keys" << std::endl;
					}
#ifdef DEBUGYAOSERVER
					std::cout << "Processing keys for gate " << gateid << ", perm-bit = " << (uint32_t) m_vGates[gateid].gs.yinput.pi[k] <<
					", client-cor: " << (uint32_t) m_vClientROTRcvBuf.GetBitNoMask(linbitctr) << std::endl;

					PrintKey(m_vClientInputKeys.GetArr() + m_nClientInputKexIdx * m_nSecParamBytes);
					std::cout << std::endl;
#endif
					if ((m_vClientROTRcvBuf.GetBitNoMask(linbitctr) ^ permval) == 1) {
						m_pKeyOps->XOR(m_vClientKeySndBuf[0].GetArr() + linbitctr * m_nSecParamBytes, m_vROTMasks[0].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes,
								m_bTempKeyBuf); //One - key
						m_pKeyOps->XOR(m_vClientKeySndBuf[1].GetArr() + linbitctr * m_nSecParamBytes, m_vROTMasks[1].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes,
								m_vClientInputKeys.GetArr() + m_nClientInputKexIdx * m_nSecParamBytes); //Zero - key
					} else {
						//masks remain the same
						m_pKeyOps->XOR(m_vClientKeySndBuf[0].GetArr() + linbitctr * m_nSecParamBytes, m_vROTMasks[0].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes,
								m_vClientInputKeys.GetArr() + m_nClientInputKexIdx * m_nSecParamBytes); //Zero - key
						m_pKeyOps->XOR(m_vClientKeySndBuf[1].GetArr() + linbitctr * m_nSecParamBytes, m_vROTMasks[1].GetArr() + m_nClientInputKexIdx * m_nSecParamBytes,
								m_bTempKeyBuf); //One - key
					}
				}
				UsedGate(input);
			}
		}
	}

	m_vClientInputGate.clear();
	m_nClientInBitCtr = 0;

	if (m_nOutputShareRcvCtr > 0) {
		AssignOutputShares();
	}

	//Recheck if this is working
	InitNewLayer();
}
;

void YaoServerSharing::GetBuffersToReceive(std::vector<BYTE*>& rcvbuf, std::vector<uint64_t>& rcvbytes) {
	//receive bit from random-OT
	if (m_nClientInBitCtr > 0) {
#ifdef DEBUGYAOSERVER
		std::cout << "want to receive clients OT-bits which are of size " << m_nClientInBitCtr << " bits" << std::endl;
#endif
		m_vClientROTRcvBuf.Create(m_nClientInBitCtr);
		rcvbuf.push_back(m_vClientROTRcvBuf.GetArr());
		rcvbytes.push_back(ceil_divide(m_nClientInBitCtr, 8));
	}

	if (m_nOutputShareRcvCtr > 0) {
#ifdef DEBUGYAOSERVER
		std::cout << "want to receive server output bits which are of size " << m_nOutputShareRcvCtr << " bits" << std::endl;
#endif
		m_vOutputShareRcvBuf.Create(m_nOutputShareRcvCtr);
		rcvbuf.push_back(m_vOutputShareRcvBuf.GetArr());
		rcvbytes.push_back(ceil_divide(m_nOutputShareRcvCtr, 8));
	}
}

void YaoServerSharing::AssignOutputShares() {
	GATE* gate;
	for (uint32_t i = 0, offset = 0; i < m_vServerOutputGates.size(); i++) {
		gate = m_vServerOutputGates[i];
#ifdef DEBUGYAOSERVER
		std::cout << "Server Output: " << (uint32_t) (m_vOutputShareRcvBuf.GetBit(offset) ^ gate->gs.val[0] ) << " = "<< (uint32_t) m_vOutputShareRcvBuf.GetBit(offset) << " ^ " << (uint32_t) gate->gs.val[0] << std::endl;
#endif
		//InstantiateGate(gate);
		for (uint32_t j = 0; j < gate->nvals; j++, offset++) {
			gate->gs.val[j / GATE_T_BITS] = (gate->gs.val[j / GATE_T_BITS] ^ (((UGATE_T) m_vOutputShareRcvBuf.GetBit(offset))) << (j % GATE_T_BITS));
		}
	}
	m_nOutputShareRcvCtr = 0;
	m_vServerOutputGates.clear();

}

void YaoServerSharing::CreateRandomWireKeys(CBitVector& vec, uint32_t numkeys) {
	//Create the random keys
	vec.Create(numkeys * m_cCrypto->get_seclvl().symbits, m_cCrypto);
	for (uint32_t i = 0; i < numkeys; i++) {
		vec.ANDByte((i + 1) * m_nSecParamBytes - 1, 0xFE);
	}
#ifdef DEBUGYAOSERVER
	std::cout << "Created wire keys: with num = " << numkeys << std::endl;
	vec.PrintHex();
	std::cout << "m_vR = " <<std::endl;
	m_vR.PrintHex();
#endif
}

void YaoServerSharing::InstantiateGate(GATE* gate) {
	gate->gs.yinput.outKey = (BYTE*) malloc(sizeof(UGATE_T) * m_nSecParamIters * gate->nvals);
	gate->gs.yinput.pi = (BYTE*) malloc(sizeof(BYTE) * gate->nvals);
	if (gate->gs.yinput.outKey == NULL) {
		std::cerr << "Memory allocation not successful at Yao gate instantiation" << std::endl;
		std::exit(EXIT_FAILURE);
	}
	gate->instantiated = true;
}

void YaoServerSharing::EvaluateSIMDGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	if (gate->type == G_COMBINE) {
		uint32_t* inptr = gate->ingates.inputs.parents; //gate->gs.cinput;
		uint32_t nparents = gate->ingates.ningates;
		uint32_t parent_nvals;
		InstantiateGate(gate);
		BYTE* keyptr = gate->gs.yinput.outKey;
		BYTE* piptr = gate->gs.yinput.pi;
		for(uint32_t g = 0; g < nparents; g++) {
			parent_nvals = m_vGates[inptr[g]].nvals;
			memcpy(keyptr, m_vGates[inptr[g]].gs.yinput.outKey, m_nSecParamBytes * parent_nvals);
			keyptr += m_nSecParamBytes * parent_nvals;

			memcpy(piptr, m_vGates[inptr[g]].gs.yinput.pi, parent_nvals);
			piptr += parent_nvals;

			UsedGate(inptr[g]);
		}
		free(inptr);
	} else if (gate->type == G_SPLIT) {
		uint32_t pos = gate->gs.sinput.pos;
		uint32_t idleft = gate->ingates.inputs.parent; //gate->gs.sinput.input;
		InstantiateGate(gate);
		memcpy(gate->gs.yinput.outKey, m_vGates[idleft].gs.yinput.outKey + pos * m_nSecParamBytes, m_nSecParamBytes * gate->nvals);
		memcpy(gate->gs.yinput.pi, m_vGates[idleft].gs.yinput.pi + pos, gate->nvals);
		UsedGate(idleft);
	} else if (gate->type == G_REPEAT) {
		uint32_t idleft = gate->ingates.inputs.parent; //gate->gs.rinput;
		InstantiateGate(gate);
		BYTE* keyptr = gate->gs.yinput.outKey;
		for (uint32_t g = 0; g < gate->nvals; g++, keyptr += m_nSecParamBytes) {
			memcpy(keyptr, m_vGates[idleft].gs.yinput.outKey, m_nSecParamBytes);
			gate->gs.yinput.pi[g] = m_vGates[idleft].gs.yinput.pi[0];
			assert(gate->gs.yinput.pi[g] < 2);
		}
		UsedGate(idleft);
	} else if (gate->type == G_COMBINEPOS) {
		uint32_t* combinepos = gate->ingates.inputs.parents; //gate->gs.combinepos.input;
		uint32_t pos = gate->gs.combinepos.pos;
		InstantiateGate(gate);
		BYTE* keyptr = gate->gs.yinput.outKey;
		for (uint32_t g = 0; g < gate->nvals; g++, keyptr += m_nSecParamBytes) {
			uint32_t idleft = combinepos[g];
			memcpy(keyptr, m_vGates[idleft].gs.yinput.outKey + pos * m_nSecParamBytes, m_nSecParamBytes);
			gate->gs.yinput.pi[g] = m_vGates[idleft].gs.yinput.pi[pos];
			assert(gate->gs.yinput.pi[g] < 2);
			UsedGate(idleft);
		}
		free(combinepos);
	} else if (gate->type == G_SUBSET) {
		uint32_t idparent = gate->ingates.inputs.parent;
		uint32_t* positions = gate->gs.sub_pos.posids; //gate->gs.combinepos.input;
		bool del_pos = gate->gs.sub_pos.copy_posids;

		InstantiateGate(gate);
		BYTE* keyptr = gate->gs.yinput.outKey;
		for (uint32_t g = 0; g < gate->nvals; g++, keyptr += m_nSecParamBytes) {
			memcpy(keyptr, m_vGates[idparent].gs.yinput.outKey + positions[g] * m_nSecParamBytes, m_nSecParamBytes);
			gate->gs.yinput.pi[g] = m_vGates[idparent].gs.yinput.pi[positions[g]];
			assert(gate->gs.yinput.pi[g] < 2);
		}
		UsedGate(idparent);
		if(del_pos)
			free(positions);
	}
}

uint32_t YaoServerSharing::AssignInput(CBitVector& inputvals) {
	std::deque<uint32_t> myingates = m_cBoolCircuit->GetInputGatesForParty(m_eRole);
	inputvals.Create(m_cBoolCircuit->GetNumInputBitsForParty(m_eRole), m_cCrypto);

	GATE* gate;
	uint32_t inbits = 0;
	for (uint32_t i = 0, inbitstart = 0, bitstocopy, len, lim; i < myingates.size(); i++) {
		gate = &(m_vGates[myingates[i]]);
		if (!gate->instantiated) {
			bitstocopy = gate->nvals * gate->sharebitlen;
			inbits += bitstocopy;
			lim = ceil_divide(bitstocopy, GATE_T_BITS);

			UGATE_T* inval = (UGATE_T*) calloc(lim, sizeof(UGATE_T));

			for (uint32_t j = 0; j < lim; j++, bitstocopy -= GATE_T_BITS) {
				len = std::min(bitstocopy, (uint32_t) GATE_T_BITS);
				inval[j] = inputvals.Get<UGATE_T>(inbitstart, len);
				inbitstart += len;
			}
			gate->gs.ishare.inval = inval;
		}
	}
	return inbits;
}

uint32_t YaoServerSharing::GetOutput(CBitVector& out) {
	std::deque<uint32_t> myoutgates = m_cBoolCircuit->GetOutputGatesForParty(m_eRole);
	uint32_t outbits = m_cBoolCircuit->GetNumOutputBitsForParty(m_eRole);
	out.Create(outbits);

	GATE* gate;
	for (uint32_t i = 0, outbitstart = 0, lim; i < myoutgates.size(); i++) {
		gate = &(m_vGates[myoutgates[i]]);
		lim = gate->nvals * gate->sharebitlen;

		for (uint32_t j = 0; j < lim; j++, outbitstart++) {
			out.SetBitNoMask(outbitstart, (gate->gs.val[j / GATE_T_BITS] >> (j % GATE_T_BITS)) & 0x01);
		}
	}
	return outbits;
}

void YaoServerSharing::Reset() {
	m_vR.delCBitVector();
	m_vPermBits.delCBitVector();

	for (uint32_t i = 0; i < m_vROTMasks.size(); i++)
		m_vROTMasks[i].delCBitVector();

	m_nClientInputKexIdx = 0;

	m_vServerKeySndBuf.delCBitVector();
	for (uint32_t i = 0; i < m_vClientKeySndBuf.size(); i++)
		m_vClientKeySndBuf[i].delCBitVector();

	m_vClientROTRcvBuf.delCBitVector();

	m_vOutputShareSndBuf.delCBitVector();
	m_vOutputShareRcvBuf.delCBitVector();

	m_nOutputShareRcvCtr = 0;

	m_nPermBitCtr = 0;
	m_nServerInBitCtr = 0;

	m_nServerKeyCtr = 0;
	m_nClientInBitCtr = 0;

	m_vClientInputGate.clear();
	m_vANDGates.clear();
	m_vOutputShareGates.clear();
	m_vServerOutputGates.clear();

	free(m_vOutputDestionations);
	m_vOutputDestionations = nullptr;
	m_nOutputDestionationsCtr = 0;

	m_nANDGates = 0;
	m_nXORGates = 0;

	m_nInputShareSndSize = 0;
	m_nOutputShareSndSize = 0;

	m_nInputShareRcvSize = 0;
	m_nOutputShareRcvSize = 0;

	m_nConversionInputBits = 0;

	m_nClientInputBits = 0;
	m_vClientInputKeys.delCBitVector();

	m_nServerInputBits = 0;
	m_vServerInputKeys.delCBitVector();

	m_vGarbledCircuit.delCBitVector();
	m_nGarbledTableCtr = 0;
	m_nGarbledTableSndCtr = 0L;

	m_vUniversalGateTable.delCBitVector();
	m_nUniversalGateTableCtr = 0;

	m_cBoolCircuit->Reset();
}
