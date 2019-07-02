/**
 \file 		yaoclientsharing.cpp
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
 \brief		Yao Client Sharing class implementation.
 */
#include "yaoclientsharing.h"
#include "../aby/abysetup.h"
#include <cstdlib>

void YaoClientSharing::InitClient() {

	m_nChoiceBitCtr = 0;
	m_vROTCtr = 0;

	m_nClientSndOTCtr = 0;
	m_nClientRcvKeyCtr = 0;
	m_nServerInBitCtr = 0;
	m_nClientOutputShareCtr = 0;
	m_nServerOutputShareCtr = 0;
	m_nClientOUTBitCtr = 0;

	m_nKeyInputRcvIdx = 0;

	m_vClientKeyRcvBuf.resize(2);

	fMaskFct = new XORMasking(m_cCrypto->get_seclvl().symbits);

	m_vTmpEncBuf = (uint8_t**) malloc(sizeof(uint8_t*) * KEYS_PER_GATE_IN_TABLE);
	for(uint32_t i = 0; i < KEYS_PER_GATE_IN_TABLE; i++)
		m_vTmpEncBuf[i] = (uint8_t*) malloc(sizeof(uint8_t) * AES_BYTES);

}

YaoClientSharing::~YaoClientSharing() {
		Reset();
		for(size_t i = 0; i < KEYS_PER_GATE_IN_TABLE; i++) {
			free(m_vTmpEncBuf[i]);
		}
		free(m_vTmpEncBuf);
		delete fMaskFct;
}

//Pre-set values for new layer
void YaoClientSharing::InitNewLayer() {
	m_nServerInBitCtr = 0;
	m_vServerInputGates.clear();

	m_nServerOutputShareCtr = 0;

}

/* Send a new task for pre-computing the OTs in the setup phase */
void YaoClientSharing::PrepareSetupPhase(ABYSetup* setup) {
	BYTE* buf;
	uint64_t gt_size;
	uint64_t univ_size;
	m_nANDGates = m_cBoolCircuit->GetNumANDGates();
	m_nUNIVGates = m_cBoolCircuit->GetNumUNIVGates();

	gt_size = ((uint64_t) m_nANDGates) * KEYS_PER_GATE_IN_TABLE * m_nSecParamBytes;
	univ_size = ((uint64_t) m_nUNIVGates) * KEYS_PER_UNIV_GATE_IN_TABLE * m_nSecParamBytes;

	if (m_cBoolCircuit->GetMaxDepth() == 0)
		return;

	//TODO figure out which parts of the init can be moved to prepareonlinephase
	/* Preset the number of input bits for client and server */
	m_nServerInputBits = m_cBoolCircuit->GetNumInputBitsForParty(SERVER);
	m_nClientInputBits = m_cBoolCircuit->GetNumInputBitsForParty(CLIENT);
	m_nConversionInputBits = m_cBoolCircuit->GetNumB2YGates() + m_cBoolCircuit->GetNumA2YGates() + m_cBoolCircuit->GetNumYSwitchGates();

	buf = (BYTE*) malloc(gt_size);
	m_vGarbledCircuit.AttachBuf(buf, gt_size);

	m_vUniversalGateTable.Create(0);
	buf = (BYTE*) malloc(univ_size);
	m_vUniversalGateTable.AttachBuf(buf, univ_size);

	m_nUniversalGateTableCtr = 0;

	m_vOutputShareRcvBuf.Create((uint32_t) m_cBoolCircuit->GetNumOutputBitsForParty(CLIENT));
	m_vOutputShareSndBuf.Create((uint32_t) m_cBoolCircuit->GetNumOutputBitsForParty(SERVER));
	m_vROTSndBuf.Create((uint32_t) m_cBoolCircuit->GetNumInputBitsForParty(CLIENT) + m_nConversionInputBits);

	m_vROTMasks.Create((m_nClientInputBits + m_nConversionInputBits) * m_cCrypto->get_seclvl().symbits); //TODO: do a bit more R-OTs to get the offset right

	m_vChoiceBits.Create(m_nClientInputBits + m_nConversionInputBits, m_cCrypto);

#ifdef DEBUGYAOCLIENT
	std::cout << "OT Choice bits: " << std::endl;
	m_vChoiceBits.Print(0, m_nClientInputBits + m_nConversionInputBits);
#endif
	/* Use the standard XORMasking function */

	/* Define the new OT tasks that will be done when the setup phase is performed*/
	IKNP_OTTask* task = (IKNP_OTTask*) malloc(sizeof(IKNP_OTTask));
	task->bitlen = m_cCrypto->get_seclvl().symbits;
	task->snd_flavor = Snd_R_OT;
	task->rec_flavor = Rec_OT;
	task->numOTs = m_nClientInputBits + m_nConversionInputBits;
	task->mskfct = fMaskFct;
	task->delete_mskfct = FALSE; // is deleted in destructor
	task->pval.rcvval.C = &(m_vChoiceBits);
	task->pval.rcvval.R = &(m_vROTMasks);

	setup->AddOTTask(task, m_eContext == S_YAO? 0 : 1);
}

/* If played as server send the garbled table, if played as client receive the garbled table */
void YaoClientSharing::PerformSetupPhase(ABYSetup* setup) {
	if (m_cBoolCircuit->GetMaxDepth() == 0)
		return;
	ReceiveGarbledCircuitAndOutputShares(setup);
}

void YaoClientSharing::PrepareOnlinePhase() {
	InitNewLayer();
}

void YaoClientSharing::ReceiveGarbledCircuitAndOutputShares(ABYSetup* setup) {
	if (m_nANDGates > 0)
		setup->AddReceiveTask(m_vGarbledCircuit.GetArr(), ((uint64_t) m_nANDGates) * m_nSecParamBytes * KEYS_PER_GATE_IN_TABLE);
	if (m_nUNIVGates > 0)
		setup->AddReceiveTask(m_vUniversalGateTable.GetArr(), ((uint64_t) m_nUNIVGates) * m_nSecParamBytes * KEYS_PER_UNIV_GATE_IN_TABLE);
	if (m_cBoolCircuit->GetNumOutputBitsForParty(CLIENT) > 0)
		setup->AddReceiveTask(m_vOutputShareRcvBuf.GetArr(), ceil_divide(m_cBoolCircuit->GetNumOutputBitsForParty(CLIENT), 8));

}

void YaoClientSharing::FinishSetupPhase(ABYSetup* setup) {
	//wait for transmission end of GC
	setup->WaitForTransmissionEnd();
	/*std::cout << "Garbled Table Cl: " << std::endl;
	m_vGarbledCircuit.PrintHex(0, ((uint64_t) m_nANDGates) * m_nSecParamBytes * KEYS_PER_GATE_IN_TABLE);

	std::cout << "Outshares C: " << std::endl;
	m_vOutputShareRcvBuf.PrintHex(ceil_divide(m_cBoolCircuit->GetNumOutputBitsForParty(CLIENT), 8));*/
#ifdef DEBUGYAOCLIENT
	std::cout << "Received Garbled Circuit: ";
	m_vGarbledCircuit.PrintHex();
	std::cout << "Received my output shares: ";
	m_vOutputShareRcvBuf.Print(0, m_cBoolCircuit->GetNumOutputBitsForParty(CLIENT));

	if(m_cBoolCircuit->GetMaxDepth() == 0)
	return;
	std::cout << "Choice bits in OT: ";
	m_vChoiceBits.Print(0, m_nClientInputBits);
	std::cout << "Resulting R from OT: ";
	m_vROTMasks.PrintHex();
#endif
}
void YaoClientSharing::EvaluateLocalOperations(uint32_t depth) {

	std::deque<uint32_t> localops = m_cBoolCircuit->GetLocalQueueOnLvl(depth);

	//std::cout << "In total I have " <<  localops.size() << " local operations to evaluate on this level " << std::endl;
	for (uint32_t i = 0; i < localops.size(); i++) {
		GATE* gate = &(m_vGates[localops[i]]);
		//std::cout << "Evaluating gate " << localops[i] << " with context = " << gate->context << std::endl;
		if (gate->type == G_LIN) {
			EvaluateXORGate(gate);
		} else if (gate->type == G_NON_LIN) {
			EvaluateANDGate(gate);
		} else if (gate->type == G_CONSTANT) {
			InstantiateGate(gate);
			memset(gate->gs.yval, 0, m_nSecParamBytes * gate->nvals);
		} else if (IsSIMDGate(gate->type)) {
			//std::cout << "Evaluating SIMD gate" << std::endl;
			EvaluateSIMDGate(localops[i]);
		} else if (gate->type == G_INV) {
			//only copy values, SERVER did the inversion
			uint32_t parentid = gate->ingates.inputs.parent; // gate->gs.invinput;
			InstantiateGate(gate);
			memcpy(gate->gs.yval, m_vGates[parentid].gs.yval, m_nSecParamBytes * gate->nvals);
			UsedGate(parentid);
		} else if (gate->type == G_SHARED_OUT) {
			GATE* parent = &(m_vGates[gate->ingates.inputs.parent]);
			InstantiateGate(gate);
			memcpy(gate->gs.yval, parent->gs.yval, gate->nvals * m_nSecParamBytes);
			UsedGate(gate->ingates.inputs.parent);
			// TODO this currently copies both keys and bits and getclearvalue will probably fail.
			//std::cerr << "SharedOutGate is not properly tested for Yao!" << std::endl;
		} else if(gate->type == G_SHARED_IN) {
			//Do nothing
		} else if(gate->type == G_CALLBACK) {
			EvaluateCallbackGate(localops[i]);
		} else if(gate->type == G_PRINT_VAL) {
			EvaluatePrintValGate(localops[i], C_BOOLEAN);
		} else if(gate->type == G_ASSERT) {
			EvaluateAssertGate(localops[i], C_BOOLEAN);
		} else if (gate->type == G_UNIV) {
			//cout << "Client: Evaluating Universal Circuit gate" << std::endl;
			EvaluateUNIVGate(gate);
		} else {
			std::cerr << "YaoClientSharing: Non-interactive operation not recognized: " <<
					(uint32_t) gate->type << "(" << get_gate_type_name(gate->type) << ")" << std::endl;
			std::exit(EXIT_FAILURE);
		}
	}
}

void YaoClientSharing::EvaluateInteractiveOperations(uint32_t depth) {
	std::deque<uint32_t> interactiveops = m_cBoolCircuit->GetInteractiveQueueOnLvl(depth);

	//std::cout << "In total I have " <<  localops.size() << " local operations to evaluate on this level " << std::endl;
	for (uint32_t i = 0; i < interactiveops.size(); i++) {
		GATE* gate = &(m_vGates[interactiveops[i]]);
#ifdef DEBUGYAOCLIENT
		std::cout << "Evaluating interactive operation in Yao client sharing with type = " << get_gate_type_name(gate->type) << std::endl;
#endif
		if (gate->type == G_IN) {
			if (gate->gs.ishare.src == SERVER) {
				ReceiveServerKeys(interactiveops[i]);
				//Receive servers input shares;
			} else {
				ReceiveClientKeys(interactiveops[i]);
				//Receive servers input shares;
			}
		} else if (gate->type == G_OUT) {
#ifdef DEBUGYAOCLIENT
			std::cout << "Obtained output gate with key = ";
			PrintKey(m_vGates[gate->ingates.inputs.parent].gs.yval);
			std::cout << std::endl;
#endif
			if (gate->gs.oshare.dst == SERVER) {
				EvaluateServerOutputGate(gate);
			} else if (gate->gs.oshare.dst == ALL) {
				//std::cout << "Output gate for both of us, sending server output for gateid: " << interactiveops[i] << std::endl;
				EvaluateServerOutputGate(gate);
				//std::cout << "Setting my output gate" << std::endl;
				EvaluateClientOutputGate(interactiveops[i]);
				//std::cout << "finished setting my output" <<std::endl;
			} else {
				//ouput reconstruction
				EvaluateClientOutputGate(interactiveops[i]);
			}
		} else if (gate->type == G_CONV) {
			EvaluateConversionGate(interactiveops[i]);
		} else if(gate->type == G_CALLBACK) {
			EvaluateCallbackGate(interactiveops[i]);
		} else {
			std::cerr << "YaoClientSharing: Interactive operation not recognized: " << (uint32_t) gate->type << "(" <<
					get_gate_type_name(gate->type) << ")" << std::endl;
		}
	}
}

void YaoClientSharing::EvaluateXORGate(GATE* gate) {
	uint32_t nvals = gate->nvals;
	uint32_t idleft = gate->ingates.inputs.twin.left; //gate->gs.ginput.left;
	uint32_t idright = gate->ingates.inputs.twin.right; //gate->gs.ginput.right;

	InstantiateGate(gate);
	//TODO: optimize for uint64_t pointers, there might be some problems here, code is untested
	/*for(uint32_t i = 0; i < m_nSecParamBytes * nvals; i++) {
	 gate->gs.yval[i] = m_vGates[idleft].gs.yval[i] ^ m_vGates[idright].gs.yval[i];
	 }*/
	//std::cout << "doing " << m_nSecParamIters << "iters on " << nvals << " vals " << std::endl;
	for (uint32_t i = 0; i < m_nSecParamIters * nvals; i++) {
		((UGATE_T*) gate->gs.yval)[i] = ((UGATE_T*) m_vGates[idleft].gs.yval)[i] ^ ((UGATE_T*) m_vGates[idright].gs.yval)[i];
	}
	//std::cout << "Keyval (" << 0 << ")= " << (gate->gs.yval[m_nSecParamBytes-1] & 0x01)  << std::endl;
	//std::cout << (gate->gs.yval[m_nSecParamBytes-1] & 0x01);
#ifdef DEBUGYAOCLIENT
	PrintKey(gate->gs.yval);
	std::cout << " = ";
	PrintKey(m_vGates[idleft].gs.yval);
	std::cout << " (" << idleft << ") ^ ";
	PrintKey(m_vGates[idright].gs.yval);
	std::cout << " (" << idright << ")" << std::endl;
#endif

	UsedGate(idleft);
	UsedGate(idright);
}

void YaoClientSharing::EvaluateANDGate(GATE* gate) {
	uint32_t idleft = gate->ingates.inputs.twin.left; //gate->gs.ginput.left;
	uint32_t idright = gate->ingates.inputs.twin.right; //gate->gs.ginput.right;
	GATE* gleft = &(m_vGates[idleft]);
	GATE* gright = &(m_vGates[idright]);

	//evaluate garbled table
	InstantiateGate(gate);
	for (uint32_t g = 0; g < gate->nvals; g++) {
		EvaluateGarbledTable(gate, g, gleft, gright);
		m_nGarbledTableCtr++;

		//Pipelined receive - TODO: outsource in own thread
		/*if(andctr >= GARBLED_TABLE_WINDOW) {
		 gtsize = std::min(remandgates, GARBLED_TABLE_WINDOW);
		 sock.Receive(m_vGarbledTables.GetArr(), gtsize * KEYS_PER_GATE_IN_TABLE * BYTES_SSP);
		 remandgates -= gtsize;
		 andctr=0;
		 }*/

	}
	UsedGate(idleft);
	UsedGate(idright);
}

BOOL YaoClientSharing::EvaluateGarbledTable(GATE* gate, uint32_t pos, GATE* gleft, GATE* gright)
{

	uint8_t *lkey, *rkey, *okey, *gtptr;
	uint8_t lpbit, rpbit;

	okey = gate->gs.yval + pos * m_nSecParamBytes;
	lkey = gleft->gs.yval + pos * m_nSecParamBytes;
	rkey = gright->gs.yval + pos * m_nSecParamBytes;
	gtptr = m_vGarbledCircuit.GetArr() + m_nSecParamBytes * KEYS_PER_GATE_IN_TABLE * m_nGarbledTableCtr;

	lpbit = lkey[m_nSecParamBytes-1] & 0x01;
	rpbit = rkey[m_nSecParamBytes-1] & 0x01;

	assert(lpbit < 2 && rpbit < 2);

	EncryptWire(m_vTmpEncBuf[0], lkey, KEYS_PER_GATE_IN_TABLE*m_nGarbledTableCtr);
	EncryptWire(m_vTmpEncBuf[1], rkey, KEYS_PER_GATE_IN_TABLE*m_nGarbledTableCtr+1);

	m_pKeyOps->XOR(okey, m_vTmpEncBuf[0], m_vTmpEncBuf[1]);//gc_xor(okey, encbuf[0], encbuf[1]);

	if(lpbit) {
		m_pKeyOps->XOR(okey, okey, gtptr);//gc_xor(okey, okey, gtptr);
	}
	if(rpbit) {
		m_pKeyOps->XOR(okey, okey, gtptr+m_nSecParamBytes);//gc_xor(okey, okey, gtptr+BYTES_SSP);
		m_pKeyOps->XOR(okey, okey, lkey);//gc_xor(okey, okey, gtptr+BYTES_SSP);
	}

#ifdef DEBUGYAOCLIENT
		std::cout << " using: ";
		PrintKey(lkey);
		std::cout << " (" << (uint32_t) lpbit << ") and : ";
		PrintKey(rkey);
		std::cout << " (" << (uint32_t) rpbit << ") to : ";
		PrintKey(okey);
		std::cout << " (" << (uint32_t) (okey[m_nSecParamBytes-1] & 0x01) << ")" << std::endl;
		std::cout << "A: ";
		PrintKey(m_vTmpEncBuf[0]);
		std::cout << "; B: ";
		PrintKey(m_vTmpEncBuf[1]);
		std::cout << std::endl;
		std::cout << "Table A: ";
		PrintKey(gtptr);
		std::cout << "; Table B: ";
		PrintKey(gtptr+m_nSecParamBytes);
		std::cout << std::endl;
#endif

	return true;
}

void YaoClientSharing::EvaluateUNIVGate(GATE* gate) {
	uint32_t idleft = gate->ingates.inputs.twin.left; //gate->gs.ginput.left;
	uint32_t idright = gate->ingates.inputs.twin.right; //gate->gs.ginput.right;
	GATE* gleft = &(m_vGates[idleft]);
	GATE* gright = &(m_vGates[idright]);

	//evaluate univeral gate table
	InstantiateGate(gate);
	for (uint32_t g = 0; g < gate->nvals; g++) {
		EvaluateUniversalGate(gate, g, gleft, gright);
		m_nUniversalGateTableCtr++;
	}
	UsedGate(idleft);
	UsedGate(idright);
}


BOOL YaoClientSharing::EvaluateUniversalGate(GATE* gate, uint32_t pos, GATE* gleft, GATE* gright)
{
	BYTE *lkey, *rkey, *okey;
	uint32_t id;
	lkey = gleft->gs.yval + pos * m_nSecParamBytes;
	rkey = gright->gs.yval + pos * m_nSecParamBytes;
	okey = gate->gs.yval + pos * m_nSecParamBytes;

	id = (lkey[m_nSecParamBytes-1] & 0x01)<<1;
	id += (rkey[m_nSecParamBytes-1] & 0x01);

	//encrypt_wire((BYTE*)gate->gs.val, m_vGarbledTables.GetArr() + BYTES_SSP * (4 * andctr + id), pleft, pright, id, m_kGarble, key_buf);
	if(id == 0) {
		EncryptWireGRR3(okey, m_bZeroBuf, lkey, rkey, id);
#ifdef DEBUGYAOCLIENT
		std::cout << " decrypted : ";
		PrintKey(m_bZeroBuf);
#endif
	} else {
#ifdef DEBUGYAOCLIENT
		std::cout << " decrypted : ";
		PrintKey(m_vUniversalGateTable.GetArr() + m_nSecParamBytes * (KEYS_PER_UNIV_GATE_IN_TABLE * m_nUniversalGateTableCtr + id-1));
#endif
		EncryptWireGRR3(okey, m_vUniversalGateTable.GetArr() + m_nSecParamBytes * (KEYS_PER_UNIV_GATE_IN_TABLE * m_nUniversalGateTableCtr + id-1), lkey, rkey, id);
	}

#ifdef DEBUGYAOCLIENT
		std::cout << " using: ";
		PrintKey(lkey);
		std::cout << " and : ";
		PrintKey(rkey);
		std::cout << " to : ";
		PrintKey(okey);
		std::cout << std::endl;
#endif

	return true;
}

/* Evaluate the gate and use the servers output permutation bits to compute the output */
void YaoClientSharing::EvaluateClientOutputGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	uint32_t parentid = gate->ingates.inputs.parent; //gate->gs.oshare.parentgate;
	InstantiateGate(gate);

#ifdef DEBUGYAOCLIENT
	uint32_t in;
	std::cout << "ClientOutput: ";
#endif
	for (uint32_t i = 0; i < gate->nvals; i++) {
#ifdef DEBUGYAOCLIENT
		in = (m_vGates[parentid].gs.yval[(i + 1) * m_nSecParamBytes - 1] & 0x01);
#endif
		gate->gs.val[i / GATE_T_BITS] ^= ((((UGATE_T) m_vGates[parentid].gs.yval[(i + 1) * m_nSecParamBytes - 1] & 0x01)
				^ ((UGATE_T) m_vOutputShareRcvBuf.GetBit(m_nClientOUTBitCtr))) << (i % GATE_T_BITS));
#ifdef DEBUGYAOCLIENT
		std::cout << (uint32_t) gate->gs.val[i/GATE_T_BITS] << " = " << in << " ^ " << (uint32_t) m_vOutputShareRcvBuf.GetBit(m_nClientOUTBitCtr) << std::endl;
#endif
		m_nClientOUTBitCtr++;
	}

	UsedGate(parentid);
}

/* Copy the output shares for the server and send them later on */
void YaoClientSharing::EvaluateServerOutputGate(GATE* gate) {
	uint32_t parentid = gate->ingates.inputs.parent;	//gate->gs.oshare.parentgate;

	for (uint32_t i = 0; i < gate->nvals; i++, m_nServerOutputShareCtr++) {
		m_vOutputShareSndBuf.SetBit(m_nServerOutputShareCtr, m_vGates[parentid].gs.yval[((i + 1) * m_nSecParamBytes) - 1] & 0x01);
#ifdef DEBUGYAOCLIENT
		std::cout << "Setting ServerOutputShare to " << ((uint32_t) m_vGates[parentid].gs.yval[((i+1)*m_nSecParamBytes) - 1] & 0x01) << std::endl;
#endif
	}

	//TODO: is the gate is an output gate for both parties, uncommenting this will crash the program. FIX!
	//UsedGate(parentid);
}

/* Store the input bits of my gates to send the correlation with the R-OTs later on */
void YaoClientSharing::ReceiveClientKeys(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	UGATE_T* input = gate->gs.ishare.inval;
	m_vROTSndBuf.SetBits((BYTE*) input, (int) m_nClientSndOTCtr, gate->nvals);
	m_nClientSndOTCtr += gate->nvals;
	m_vClientSendCorrectionGates.push_back(gateid);
}

/* Add the servers input keys to the queue to receive them later on */
void YaoClientSharing::ReceiveServerKeys(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);

	m_vServerInputGates.push_back(gateid);
	m_nServerInBitCtr += gate->nvals;
}

void YaoClientSharing::EvaluateConversionGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	GATE* parent = &(m_vGates[gate->ingates.inputs.parents[0]]);
	assert(parent->instantiated);
	UGATE_T* val = parent->gs.val;

	if (parent->context == S_ARITH && (gate->gs.pos & 0x01) == 0) {
#ifdef DEBUGYAOCLIENT
		std::cout << "Server conversion gate with pos = " << gate->gs.pos << std::endl;
#endif
		m_vServerInputGates.push_back(gateid);
		m_nServerInBitCtr += gate->nvals;
	} else {
#ifdef DEBUGYAOCLIENT
		std::cout << "Client conversion gate with pos = " << gate->gs.pos << std::endl;
#endif
		if (parent->context == S_ARITH) {
			uint64_t id;
			uint8_t *tval;
			tval = (uint8_t*) calloc(ceil_divide(parent->nvals, 8), sizeof(uint8_t));
			id = gate->gs.pos >> 1;
			for(uint32_t i = 0; i < parent->nvals; i++) {
				tval[i/8] |= ((val[(id+i*parent->sharebitlen) / GATE_T_BITS] >>
						((id+i*parent->sharebitlen) % GATE_T_BITS)) & 0x01) << (i%8);
			}
			m_vROTSndBuf.SetBits((BYTE*) tval, (int) m_nClientSndOTCtr, gate->nvals);
			free(tval);
#ifdef DEBUGYAOCLIENT
			std::cout << "value of conversion gate: " << tval << std::endl;
#endif
		} else if (parent->context == S_BOOL){
			m_vROTSndBuf.SetBits((BYTE*) val, (int) m_nClientSndOTCtr, gate->nvals);
#ifdef DEBUGYAOCLIENT
			std::cout << "value of conversion gate: " << val[0] << std::endl;
#endif
		} else if(parent->context == S_YAO || parent->context == S_YAO_REV) {
			for(uint32_t i = 0; i < parent->nvals; i++) {
				m_vROTSndBuf.SetBits(parent->gs.yinput.pi+i, (int) m_nClientSndOTCtr+i, 1);
				//std::cout << "Client conv share = " << (uint32_t) parent->gs.yinput.pi[i] << std::endl;
			}
		}
		else{
			std::cerr << "Error: unkown parent context: " << parent->context << std::endl;
		}
		m_nClientSndOTCtr += gate->nvals;
		m_vClientSendCorrectionGates.push_back(gateid);
	}
}

//TODO bits in ROTMasks are not going to be aligned later on, recheck
void YaoClientSharing::GetDataToSend(std::vector<BYTE*>& sendbuf, std::vector<uint64_t>& sndbytes) {
	//Send the correlation bits with the random OTs
	if (m_nClientSndOTCtr > 0) {
#ifdef DEBUGYAOCLIENT
		std::cout << "want to send client OT-bits which are of size " << m_nClientSndOTCtr << " bits" << std::endl;
#endif
		m_vROTSndBuf.XORBitsPosOffset(m_vChoiceBits.GetArr(), m_nChoiceBitCtr, 0, m_nClientSndOTCtr);
#ifdef DEBUGYAOCLIENT
		std::cout << "Sending corrections: ";
		m_vROTSndBuf.Print(0, m_nClientSndOTCtr);
		std::cout << " = value ^ ";
		m_vChoiceBits.Print(m_nChoiceBitCtr, m_nChoiceBitCtr + m_nClientSndOTCtr);
#endif
		sendbuf.push_back(m_vROTSndBuf.GetArr());
		sndbytes.push_back(ceil_divide(m_nClientSndOTCtr, 8));
		m_nChoiceBitCtr += m_nClientSndOTCtr;
	}

	if (m_nServerOutputShareCtr > 0) {
#ifdef DEBUGYAOCLIENT
		std::cout << "want to send server output shares which are of size " << m_nServerOutputShareCtr << " bits" << std::endl;
#endif
		sendbuf.push_back(m_vOutputShareSndBuf.GetArr());
		sndbytes.push_back(ceil_divide(m_nServerOutputShareCtr, 8));
	}

#ifdef DEBUGYAO
	if(m_nInputShareSndSize > 0) {
		std::cout << "Sending " << m_nInputShareSndSize << " Input shares : ";
		m_vInputShareSndBuf.Print(0, m_nInputShareSndSize);
	}
	if(m_nOutputShareSndSize > 0) {
		std::cout << "Sending " << m_nOutputShareSndSize << " Output shares : ";
		m_vOutputShareSndBuf.Print(0, m_nOutputShareSndSize);
	}
#endif
}

/* Register the values that are to be received in this iteration */
void YaoClientSharing::GetBuffersToReceive(std::vector<BYTE*>& rcvbuf, std::vector<uint64_t>& rcvbytes) {
	//Receive servers keys
	if (m_nServerInBitCtr > 0) {
#ifdef DEBUGYAOCLIENT
		std::cout << "want to receive servers input keys which are of size " << (m_nServerInBitCtr * m_nSecParamBytes) << " bytes" << std::endl;
#endif
		m_vServerInputKeys.Create(m_nServerInBitCtr * m_cCrypto->get_seclvl().symbits);
		rcvbuf.push_back(m_vServerInputKeys.GetArr());
		rcvbytes.push_back(m_nServerInBitCtr * m_nSecParamBytes);
	}

	if (m_nClientRcvKeyCtr > 0) {
#ifdef DEBUGYAOCLIENT
		std::cout << "want to receive client input keys which are of size 2* " << m_nClientRcvKeyCtr * m_nSecParamBytes << " bytes" << std::endl;
#endif
		m_vClientKeyRcvBuf[0].Create(m_nClientRcvKeyCtr * m_cCrypto->get_seclvl().symbits);
		rcvbuf.push_back(m_vClientKeyRcvBuf[0].GetArr());
		rcvbytes.push_back(m_nClientRcvKeyCtr * m_nSecParamBytes);

		m_vClientKeyRcvBuf[1].Create(m_nClientRcvKeyCtr * m_cCrypto->get_seclvl().symbits);
		rcvbuf.push_back(m_vClientKeyRcvBuf[1].GetArr());
		rcvbytes.push_back(m_nClientRcvKeyCtr * m_nSecParamBytes);
	}
}

void YaoClientSharing::FinishCircuitLayer() {
	//Assign the servers input keys that were received this round
	if (m_nServerInBitCtr > 0)
		AssignServerInputKeys();

	//Assign the clients input keys that were received this round
	if (m_nClientRcvKeyCtr > 0) {
		AssignClientInputKeys();
	}

	//Assign the clients input keys to the gates
	if (m_nClientSndOTCtr > 0) {
		m_nClientRcvKeyCtr = m_nClientSndOTCtr;
		m_nClientSndOTCtr = 0;
		//TODO optimize
		for (uint32_t i = 0; i < m_vClientSendCorrectionGates.size(); i++) {
			m_vClientRcvInputKeyGates.push_back(m_vClientSendCorrectionGates[i]);
		}
		m_vClientSendCorrectionGates.clear();
	}

	InitNewLayer();
}
;

/* Assign the received server input keys to the pushed back gates in this round */
void YaoClientSharing::AssignServerInputKeys() {
	GATE* gate;
	for (uint32_t i = 0, offset = 0; i < m_vServerInputGates.size(); i++) {
		gate = &(m_vGates[m_vServerInputGates[i]]);
		InstantiateGate(gate);
		//Assign the keys to the gate
		memcpy(gate->gs.yval, m_vServerInputKeys.GetArr() + offset, m_nSecParamBytes * gate->nvals);
		offset += (m_nSecParamBytes * gate->nvals);
#ifdef DEBUGYAOCLIENT
		std::cout << "assigned server input key: ";
		PrintKey(gate->gs.yval);
		std::cout << std::endl;
#endif
	}
	m_vServerInputGates.clear();

	m_nServerInBitCtr = 0;
}

/* Assign the received server input keys to the pushed back gates in this round */
void YaoClientSharing::AssignClientInputKeys() {
	GATE* gate;
	for (uint32_t i = 0, offset = 0; i < m_vClientRcvInputKeyGates.size(); i++) {
		gate = &(m_vGates[m_vClientRcvInputKeyGates[i]]);
		//input = ;

		InstantiateGate(gate);
		//Assign the keys to the gate, TODO XOR with R-OT masks
		for (uint32_t j = 0; j < gate->nvals; j++, m_nKeyInputRcvIdx++, offset++) {
			m_pKeyOps->XOR(gate->gs.yval + j * m_nSecParamBytes,
					m_vClientKeyRcvBuf[m_vChoiceBits.GetBitNoMask(m_nKeyInputRcvIdx)].GetArr() + offset * m_nSecParamBytes,
					m_vROTMasks.GetArr() + m_nKeyInputRcvIdx * m_nSecParamBytes);
#ifdef DEBUGYAOCLIENT
			std::cout << "assigned client input key to gate " << m_vClientRcvInputKeyGates[i] << ": ";
			PrintKey(gate->gs.yval);
			std::cout << " (" << (uint32_t) m_vChoiceBits.GetBitNoMask(m_nKeyInputRcvIdx) << ") = " << std::endl;
			PrintKey( m_vClientKeyRcvBuf[m_vChoiceBits.GetBitNoMask(m_nKeyInputRcvIdx)].GetArr() + offset * m_nSecParamBytes);
			std::cout << " ^ " << std::endl;
			PrintKey(m_vROTMasks.GetArr() + (m_nKeyInputRcvIdx) * m_nSecParamBytes);
			std::cout << std::endl;
#endif
		}
		if (gate->type == G_IN) {
			free(gate->gs.ishare.inval);
		} else {
		//if (gate->type == G_CONV) {
			//G_CONV
			free(gate->ingates.inputs.parents);
		}
	}
	m_vClientRcvInputKeyGates.clear();

	m_nClientRcvKeyCtr = 0;
}

void YaoClientSharing::InstantiateGate(GATE* gate) {
	gate->instantiated = true;
	gate->gs.yval = (BYTE*) calloc(m_nSecParamIters * gate->nvals, sizeof(UGATE_T));
}

void YaoClientSharing::EvaluateSIMDGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	if (gate->type == G_COMBINE) {
		uint32_t* inptr = gate->ingates.inputs.parents; //gate->gs.cinput;
		uint32_t nparents = gate->ingates.ningates;
		uint32_t parent_nvals;

		InstantiateGate(gate);
		BYTE* keyptr = gate->gs.yval;
		for (uint32_t g = 0; g < nparents; g++) {
			parent_nvals = m_vGates[inptr[g]].nvals;
			memcpy(keyptr, m_vGates[inptr[g]].gs.yval, m_nSecParamBytes * parent_nvals);
			keyptr += m_nSecParamBytes * parent_nvals;
			UsedGate(inptr[g]);
		}
		free(inptr);
	} else if (gate->type == G_SPLIT) {
		uint32_t pos = gate->gs.sinput.pos;
		uint32_t idleft = gate->ingates.inputs.parent; // gate->gs.sinput.input;
		InstantiateGate(gate);
		memcpy(gate->gs.yval, m_vGates[idleft].gs.yval + pos * m_nSecParamBytes, m_nSecParamBytes * gate->nvals);
		UsedGate(idleft);
	} else if (gate->type == G_REPEAT) {
		uint32_t idleft = gate->ingates.inputs.parent; //gate->gs.rinput;
		InstantiateGate(gate);
		BYTE* keyptr = gate->gs.yval;
		for (uint32_t g = 0; g < gate->nvals; g++, keyptr += m_nSecParamBytes) {
			memcpy(keyptr, m_vGates[idleft].gs.yval, m_nSecParamBytes);
		}
		UsedGate(idleft);
	} else if (gate->type == G_COMBINEPOS) {
		uint32_t* combinepos = gate->ingates.inputs.parents; //gate->gs.combinepos.input;
		uint32_t pos = gate->gs.combinepos.pos;
		InstantiateGate(gate);
		BYTE* keyptr = gate->gs.yval;
		for (uint32_t g = 0; g < gate->nvals; g++, keyptr += m_nSecParamBytes) {
			uint32_t idleft = combinepos[g];
			memcpy(keyptr, m_vGates[idleft].gs.yval + pos * m_nSecParamBytes, m_nSecParamBytes);
			UsedGate(idleft);
		}
		free(combinepos);
#ifdef ZDEBUG
		std::cout << "), size = " << size << ", and val = " << gate->gs.val[0]<< std::endl;
#endif
#ifdef DEBUGCLIENT
		std::cout << ", res: " << ((unsigned uint32_t) gate->gs.yval[BYTES_SSP-1] & 0x01) << " = " << ((unsigned uint32_t) gleft->gs.yval[BYTES_SSP-1] & 0x01) << " and " << ((unsigned uint32_t) gright->gs.yval[BYTES_SSP-1] & 0x01);
#endif
	} else if (gate->type == G_SUBSET) {
		uint32_t idparent = gate->ingates.inputs.parent;
		uint32_t* positions = gate->gs.sub_pos.posids; //gate->gs.combinepos.input;
		bool del_pos = gate->gs.sub_pos.copy_posids;

		InstantiateGate(gate);
		BYTE* keyptr = gate->gs.yval;
		for (uint32_t g = 0; g < gate->nvals; g++, keyptr += m_nSecParamBytes) {
			memcpy(keyptr, m_vGates[idparent].gs.yval + positions[g] * m_nSecParamBytes, m_nSecParamBytes);
		}
		UsedGate(idparent);
		if(del_pos)
			free(positions);
	}
}

uint32_t YaoClientSharing::AssignInput(CBitVector& inputvals) {
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

uint32_t YaoClientSharing::GetOutput(CBitVector& out) {
	std::deque<uint32_t> myoutgates = m_cBoolCircuit->GetOutputGatesForParty(m_eRole);
	uint32_t outbits = m_cBoolCircuit->GetNumOutputBitsForParty(m_eRole);
	out.Create(outbits);

	GATE* gate;
	for (uint32_t i = 0, outbitstart = 0, lim; i < myoutgates.size(); i++) {
		gate = &(m_vGates[myoutgates[i]]);
		lim = gate->nvals * gate->sharebitlen;
		std::cout << "outgate no " << i << " : " << myoutgates[i] << " with nvals = " << gate->nvals << " and sharebitlen = " << gate->sharebitlen << std::endl;

		for (uint32_t j = 0; j < lim; j++, outbitstart++) {
			out.SetBitNoMask(outbitstart, (gate->gs.val[j / GATE_T_BITS] >> (j % GATE_T_BITS)) & 0x01);
		}
	}
	return outbits;
}

void YaoClientSharing::Reset() {
	m_vROTMasks.delCBitVector();
	m_nChoiceBitCtr = 0;
	m_vChoiceBits.delCBitVector();

	m_nServerInBitCtr = 0;
	m_nClientSndOTCtr = 0;
	m_nClientRcvKeyCtr = 0;
	m_nClientOutputShareCtr = 0;
	m_nServerOutputShareCtr = 0;

	m_nClientOUTBitCtr = 0;

	m_nKeyInputRcvIdx = 0;

	m_vServerKeyRcvBuf.delCBitVector();
	for (uint32_t i = 0; i < m_vClientKeyRcvBuf.size(); i++)
		m_vClientKeyRcvBuf[i].delCBitVector();

	m_nGarbledCircuitRcvCtr = 0;

	m_vOutputShareRcvBuf.delCBitVector();
	m_vOutputShareSndBuf.delCBitVector();

	m_vClientSendCorrectionGates.clear();
	m_vServerInputGates.clear();
	m_vANDGates.clear();
	m_vOutputShareGates.clear();

	m_vROTSndBuf.delCBitVector();
	m_vROTCtr = 0;

	m_nANDGates = 0;
	m_nXORGates = 0;

	m_nConversionInputBits = 0;

	m_nInputShareSndSize = 0;
	m_nOutputShareSndSize = 0;

	m_nInputShareRcvSize = 0;
	m_nOutputShareRcvSize = 0;

	m_nClientInputBits = 0;
	m_vClientInputKeys.delCBitVector();

	m_nServerInputBits = 0;
	m_vServerInputKeys.delCBitVector();

	m_vGarbledCircuit.delCBitVector();
	m_nGarbledTableCtr = 0;

	m_vUniversalGateTable.delCBitVector();
	m_nUniversalGateTableCtr = 0;

	m_cBoolCircuit->Reset();
}
