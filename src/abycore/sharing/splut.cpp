/**
 \file 		splut.cpp
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
 \brief		Implementation of the SP-LUT protocol
 */
#include "splut.h"
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <vector>
#include "../aby/abysetup.h"
#include "../circuit/booleancircuits.h"


SetupLUT::SetupLUT(e_sharing context, e_role role, uint32_t sharebitlen, ABYCircuit* circuit, crypto* crypt, const std::string& circdir)
	: Sharing(context, role, sharebitlen, circuit, crypt, circdir) {
	Init();
}

SetupLUT::~SetupLUT() {
	Reset();
	delete m_cBoolCircuit;
}


void SetupLUT::Init() {

	uint32_t otNs = 9;

	m_vNOTs.resize(2);
	m_vNOTs[0].resize(otNs);
	m_vNOTs[1].resize(otNs);
	m_vOutBitMapping.resize(otNs);

	m_vPreCompOTX.resize(otNs);
	m_vPreCompOTMasks.resize(otNs);

	m_vPreCompOTC.resize(otNs);
	m_vPreCompOTR.resize(otNs);
	m_vTableRnd.resize(otNs);

	m_nTableRndIdx.resize(otNs);
	m_vPreCompChoiceIdx.resize(otNs);
	m_vPreCompMaskIdx.resize(otNs);
	//choice buffers for sender and receiver
	m_vChoiceUpdateSndBuf.resize(otNs);
	m_vChoiceUpdateRcvBuf.resize(otNs);
	m_nChoiceUpdateSndCtr.resize(otNs);
	m_nChoiceUpdateRcvCtr.resize(otNs);
	//mask buffers for sender and receiver
	m_vMaskUpdateSndBuf.resize(otNs);
	m_vMaskUpdateRcvBuf.resize(otNs);
	m_nMaskUpdateSndCtr.resize(otNs);
	m_nMaskUpdateRcvCtr.resize(otNs);
	m_vTTGates.resize(otNs);


	for(uint32_t i = 0; i < otNs; i++) {
		m_vNOTs[0][i].resize(1);
		m_vNOTs[0][i][0].tt_len = (1<<i);
		m_vNOTs[0][i][0].numgates = 0;
		m_vNOTs[0][i][0].out_bits = 1;

		m_vNOTs[1][i].resize(1);
		m_vNOTs[1][i][0].tt_len = (1<<i);
		m_vNOTs[1][i][0].numgates = 0;
		m_vNOTs[1][i][0].out_bits = 1;
	}

	m_nXORGates = 0;

	m_nTotalTTs = 0;

	m_nInputShareSndSize = 0;
	m_nOutputShareSndSize = 0;
	m_nInputShareRcvSize = 0;
	m_nOutputShareRcvSize = 0;

	m_cBoolCircuit = new BooleanCircuit(m_pCircuit, m_eRole, m_eContext, m_cCircuitFileDir);

	//first round: the server is the active part and skips the first send iteration while the client waits until the server is done with depth 1
	m_bPlaySender = !((bool) m_eRole);

	t_snd = 0;
	t_rcv = 0;

#ifdef BENCHBOOLTIME
	m_nCombTime = 0;
	m_nSubsetTime = 0;
	m_nCombStructTime = 0;
	m_nSIMDTime = 0;
	m_nXORTime = 0;
#endif
}

//Pre-set values for new layer
void SetupLUT::InitNewLayer() {
	//Create new random values for this layer
	if (m_nInputShareSndSize > 0) {
		uint32_t inbits = m_cBoolCircuit->GetNumInputBitsForParty(m_eRole);
		m_vInputShareSndBuf.Create(inbits, m_cCrypto);
	}

	m_nInputShareRcvSize = 0;
	m_nOutputShareRcvSize = 0;

	m_nInputShareSndSize = 0;
	m_nOutputShareSndSize = 0;

	m_vInputShareGates.clear();
	m_vOutputShareGates.clear();

	if(!m_bPlaySender) {
		//free all elements on the stash and clear
		for(uint32_t i = 0; i < m_vSndBufStash.size(); i++) {
			free(m_vSndBufStash[i]);
		}
		m_vSndBufStash.clear();
		m_vSndBytesStash.clear();
	}

	//TODO: update choices and mask buffers
	for(uint32_t i = 0; i < m_nChoiceUpdateSndCtr.size(); i++) {
		for(uint32_t j = 0; j < m_nChoiceUpdateSndCtr[i].size(); j++) {
			if(m_nChoiceUpdateSndCtr[i][j] > 0) {
				//m_vPreCompChoiceIdx[i] += m_nChoiceUpdateSndCtr[i];
				m_nChoiceUpdateSndCtr[i][j] = 0;
				//m_vChoiceUpdateSndBuf[i]->Reset();
			}
			/*if(m_nMaskUpdateSndCtr[i] > 0) {
				m_vPreCompMaskIdx[i] += m_nChoiceUpdateSndCtr[i];
				m_nMaskUpdateSndCtr[i] = 0;
				m_vMaskUpdateSndBuf[i]->Reset();
			}*/
			m_nChoiceUpdateRcvCtr[i][j] = 0;
			m_nMaskUpdateRcvCtr[i][j] = 0;
		}
	}

}

void SetupLUT::PrepareSetupPhase(ABYSetup* setup) {
	//tt_lens_ctx* tmplens;
	std::vector<std::vector<std::vector<tt_lens_ctx> > > tmplens = m_cBoolCircuit->GetTTLens();

	//Server has 1, Client has 0
	uint32_t reverse = ((uint32_t) m_bPlaySender);

	/*for(uint32_t i = 0; i < tmplens.size(); i++) {
		for(uint32_t j = 0; j < tmplens[i].size(); j++) {
			for(uint32_t k = 0; k < tmplens[i][j].size(); k++) {
				std::cout << "numgates for i = " << i << ", j = " << j << ", k = " << k << ": " << tmplens[i][j][k].numgates <<
						", len = " << tmplens[i][j][k].tt_len << ", out_bits = " << tmplens[i][j][k].out_bits << std::endl;
			}
		}
	}*/

	uint32_t max_out_bits = 0;
	std::vector<uint32_t> ingatelens(m_vNOTs[0].size(), 0);
	std::vector<uint32_t> tmpgateid(m_vNOTs[0].size(), 0);

	for(uint32_t i = 0; i < tmplens[0].size(); i++) {
		assert(1<<ceil_log2(tmplens[0][i][0].tt_len) == tmplens[0][i][0].tt_len);//check for power of two
		assert(ceil_log2(tmplens[0][i][0].tt_len) <= 8); //check that it is smaller than 8

		//std::cout << "values for " << i << " with ttlen = " << tmplens[0][i][0].tt_len << ", numgates = " <<
		//		tmplens[0][i][0].numgates << ", outbits = " << tmplens[0][i][0].out_bits << std::endl;

		ingatelens[ceil_log2(tmplens[0][i][0].tt_len)] = tmplens[0][i].size();

		tmpgateid[ceil_log2(tmplens[0][i][0].tt_len)] = i;
		//std::cout << "tmpgateid at " << ceil_log2(tmplens[0][i][0].tt_len) << " = " << tmpgateid[ceil_log2(tmplens[0][i][0].tt_len)]<<std::endl;
	}


	for(uint32_t i = 0; i < m_vNOTs[0].size(); i++) {
		//resize m_vNOTs appropriately
		m_vNOTs[0][i].resize(ingatelens[i]);
		m_vNOTs[1][i].resize(ingatelens[i]);
		max_out_bits = 0;
		for(uint32_t j = 0; j < ingatelens[i]; j++) {
			m_vNOTs[0][i][j].numgates = 0;
			m_vNOTs[1][i][j].numgates = 0;
			m_vNOTs[0][i][j].out_bits = tmplens[0][tmpgateid[i]][j].out_bits;
			m_vNOTs[1][i][j].out_bits = tmplens[0][tmpgateid[i]][j].out_bits;
			m_vNOTs[0][i][j].tt_len = tmplens[0][tmpgateid[i]][j].tt_len;
			m_vNOTs[1][i][j].tt_len = tmplens[0][tmpgateid[i]][j].tt_len;

			if(tmplens[0][tmpgateid[i]][j].out_bits > max_out_bits) {
				max_out_bits = tmplens[0][tmpgateid[i]][j].out_bits;
			}
		}
		//create the outbit mapping
		assert(max_out_bits < (uint32_t) (1<<31));//some maximal bitlen
		m_vOutBitMapping[i].resize(max_out_bits+1, 0);

		for(uint32_t j = 0; j < ingatelens[i]; j++) {
			assert(tmplens[0][tmpgateid[i]][j].out_bits < m_vOutBitMapping[i].size());
			m_vOutBitMapping[i][tmplens[0][tmpgateid[i]][j].out_bits] = j;
		}
	}


	for(uint32_t d = 0; d < tmplens.size(); d++) {
		for (uint32_t i = 0; i < tmplens[d].size(); i++) {
			assert(1<<ceil_log2(tmplens[d][i][0].tt_len) == tmplens[d][i][0].tt_len);//check for power of two
			assert(ceil_log2(tmplens[d][i][0].tt_len) <= 8); //check that it is smaller than 8

			for(uint32_t j = 0; j < tmplens[d][i].size(); j++) {
				m_vNOTs[(d&0x01)][ceil_log2(tmplens[d][i][j].tt_len)][j].numgates += tmplens[d][i][j].numgates;
				m_nTotalTTs += tmplens[d][i][j].numgates;
			}
		}
	}

	/*for(uint32_t i = 0; i < m_vNOTs.size(); i++) {
		for(uint32_t j = 0; j < m_vNOTs[i].size(); j++) {
			for(uint32_t k = 0; k < m_vNOTs[i][j].size(); k++) {
				std::cout << "m_vNOTs for i = " << i << ", j = " << j << ", k = " << k << ": " << m_vNOTs[i][j][k].numgates <<
						", len = " << m_vNOTs[i][j][k].tt_len << ", out_bits = " << m_vNOTs[i][j][k].out_bits << std::endl;
			}
		}
	}*/

	for(uint32_t i = 0; i < m_vNOTs[0].size(); i++) {
		m_vChoiceUpdateSndBuf[i].resize(m_vNOTs[0][i].size());
		m_nChoiceUpdateSndCtr[i].resize(m_vNOTs[0][i].size(), 0);
		m_vChoiceUpdateRcvBuf[i].resize(m_vNOTs[0][i].size());
		m_nChoiceUpdateRcvCtr[i].resize(m_vNOTs[0][i].size(), 0);

		m_vMaskUpdateSndBuf[i].resize(m_vNOTs[0][i].size());
		m_nMaskUpdateSndCtr[i].resize(m_vNOTs[0][i].size(), 0);
		m_vMaskUpdateRcvBuf[i].resize(m_vNOTs[0][i].size());
		m_nMaskUpdateRcvCtr[i].resize(m_vNOTs[0][i].size(), 0);

		m_vPreCompOTX[i].resize(m_vNOTs[0][i].size());
		m_vPreCompOTMasks[i].resize(m_vNOTs[0][i].size());
		m_vPreCompMaskIdx[i].resize(m_vNOTs[0][i].size(), 0);

		m_vPreCompOTC[i].resize(m_vNOTs[0][i].size());
		m_vPreCompOTR[i].resize(m_vNOTs[0][i].size());
		m_vPreCompChoiceIdx[i].resize(m_vNOTs[0][i].size(), 0);

		m_vTableRnd[i].resize(m_vNOTs[0][i].size());
		m_nTableRndIdx[i].resize(m_vNOTs[0][i].size(), 0);

		for(uint32_t k = 0; k < m_vNOTs[0][i].size(); k++) {
			//std::cout << "I am creating for " << (!reverse ? "Sender" : "Receiver") << std::endl;
			//std::cout << "Creating sender values of size " << m_vNOTs[!reverse][i].numgates << " and len = " << m_vNOTs[!reverse][i].tt_len << std::endl;
			//std::cout << "Creating receiver values of size " << m_vNOTs[reverse][i].numgates << " and len = " << m_vNOTs[!reverse][i].tt_len<< std::endl;

			m_vPreCompOTX[i][k] = (CBitVector**) malloc(sizeof(CBitVector*) * m_vNOTs[!reverse][i][k].tt_len);
			//std::cout << "Address of X = " << (uint64_t) m_vPreCompOTX[i][k] << std::endl;
			//std::cout << "Creating OTX at i = " << i << ", k = " << k << " with size " << m_vNOTs[!reverse][i][k].numgates*m_vNOTs[!reverse][i][k].out_bits <<
			//		", and ttlen = " << m_vNOTs[!reverse][i][k].tt_len << std::endl;
			//std::cout << "Address of X = " << (uint64_t) m_vPreCompOTX[i][k] << " with tt_len = " <<  m_vNOTs[!reverse][i][k].tt_len << std::endl;
			for(uint32_t j = 0; j < m_vNOTs[!reverse][i][k].tt_len; j++) {
				//std::cout << "Allocating number " << j << " with size " << (m_vNOTs[!reverse][i][k].numgates*m_vNOTs[!reverse][i][k].out_bits) << std::endl;
				//std::cout << "Address of XU = " << (uint64_t) m_vPreCompOTX[i][k] << std::endl;
				m_vPreCompOTX[i][k][j] = new CBitVector();

				m_vPreCompOTX[i][k][j]->Create(m_vNOTs[!reverse][i][k].numgates*m_vNOTs[!reverse][i][k].out_bits);//TODO Change from OLUT
				//m_vPreCompOTX[i][k][j]->Create(m_vNOTs[!reverse][i][k].numgates*m_vNOTs[!reverse][i][k].tt_len);//TODO Change from OLUT
				//std::cout << "Address = " << (uint64_t) m_vPreCompOTX[i][k][j] << std::endl;
			//	std::cout << "Address = " << (uint64_t) m_vPreCompOTX[i][j] << std::endl;
			}
			m_vTableRnd[i][k] = new CBitVector();
			m_vTableRnd[i][k]->Create(m_vNOTs[!reverse][i][k].numgates*m_vNOTs[!reverse][i][k].out_bits, m_cCrypto);

			m_vPreCompOTMasks[i][k] = new CBitVector();
			m_vPreCompOTMasks[i][k]->Create(m_vNOTs[!reverse][i][k].numgates * m_vNOTs[!reverse][i][k].tt_len  * m_vNOTs[!reverse][i][k].out_bits);//TODO Change from OLUT
			//m_vPreCompOTMasks[i][k]->Create(m_vNOTs[!reverse][i][k].numgates * m_vNOTs[!reverse][i][k].tt_len  * m_vNOTs[!reverse][i][k].tt_len);//TODO Change from OLUT

			m_vPreCompOTR[i][k] = new CBitVector();
			m_vPreCompOTR[i][k]->Create(m_vNOTs[reverse][i][k].numgates*m_vNOTs[reverse][i][k].out_bits);//TODO Change from OLUT
			//m_vPreCompOTR[i][k]->Create(m_vNOTs[reverse][i][k].numgates*m_vNOTs[reverse][i][k].tt_len);//TODO Change from OLUT
			m_vPreCompOTC[i][k] = new CBitVector();
			m_vPreCompOTC[i][k]->Create(m_vNOTs[reverse][i][k].numgates * ceil_log2(m_vNOTs[reverse][i][k].tt_len), m_cCrypto);

			m_vChoiceUpdateSndBuf[i][k] = new CBitVector();
			m_vChoiceUpdateSndBuf[i][k]->Create(m_vNOTs[reverse][i][k].numgates * ceil_log2(m_vNOTs[reverse][i][k].tt_len));
			m_vChoiceUpdateRcvBuf[i][k] = new CBitVector();
			m_vChoiceUpdateRcvBuf[i][k]->Create(m_vNOTs[!reverse][i][k].numgates * ceil_log2(m_vNOTs[!reverse][i][k].tt_len));

			m_vMaskUpdateSndBuf[i][k] = new CBitVector();
			m_vMaskUpdateSndBuf[i][k]->Create(m_vNOTs[!reverse][i][k].numgates * m_vNOTs[!reverse][i][k].tt_len  * m_vNOTs[!reverse][i][k].out_bits);
			m_vMaskUpdateRcvBuf[i][k] = new CBitVector();
			m_vMaskUpdateRcvBuf[i][k]->Create(m_vNOTs[reverse][i][k].numgates * m_vNOTs[reverse][i][k].tt_len * m_vNOTs[reverse][i][k].out_bits);
		}
	}

	if (m_nTotalTTs == 0)
		return;

	for (uint32_t i = 1; i < m_vPreCompOTX.size(); i++) {
		for(uint32_t k = 0; k < m_vPreCompOTX[i].size(); k++) {
			for (uint32_t j = 0; j < 2; j++) {
				//fMaskFct = new XORMasking(m_vNOTs[j&0x01][i][k].out_bits);
				fMaskFct = new XORMasking(m_vNOTs[j&0x01][i][k].tt_len);
				if(m_vNOTs[j&0x01][i][k].numgates > 0) {
					KK_OTTask* task = (KK_OTTask*) malloc(sizeof(KK_OTTask));
					task->bitlen = m_vNOTs[j&0x01][i][k].out_bits;//TODO Change from OLUT
					//task->bitlen = m_vNOTs[j&0x01][i][k].tt_len;//TODO Change from OLUT
					task->snd_flavor = Snd_R_OT;//TODO Change from OLUT
					//task->snd_flavor = Snd_OT;//TODO Change from OLUT
					task->rec_flavor = Rec_OT;
					task->nsndvals = 1<<i;
					task->numOTs = m_vNOTs[j&0x01][i][k].numgates;
					task->mskfct = fMaskFct;
					task->delete_mskfct = true;
					if ((reverse ^ j)) {
						//std::cout << "I assigned sender" << std::endl;
						task->pval.sndval.X = m_vPreCompOTX[i][k];
					} else {
						//std::cout << "I assigned receiver" << std::endl;
						task->pval.rcvval.C = m_vPreCompOTC[i][k];
						task->pval.rcvval.R = m_vPreCompOTR[i][k];
					}
#ifndef BATCH
					std::cout << "Adding new " << (reverse^(j&0x01)? "Sender" : "Receiver") << " KK 1oo" << task->nsndvals <<
							" OT task for " << task->numOTs << " OTs on " << task->bitlen << " bit-strings" << std::endl;
#endif
					setup->AddOTTask(task, j);
				}
			}
		}
	}

}

void SetupLUT::PerformSetupPhase([[maybe_unused]] ABYSetup* setup) {
	//Do nothing
}
void SetupLUT::FinishSetupPhase([[maybe_unused]] ABYSetup* setup) {
	if (m_nTotalTTs == 0)
		return;

	//TODO Reformat PreComputed OTs for the sender to have a faster online phase
	//ComputeMTs();
#ifdef DEBUGBOOL_NO_MT
	//if(m_eRole == SERVER) {
	uint32_t reverse = ((uint32_t) !m_bPlaySender);

	for(uint32_t i = 1; i < m_vPreCompOTX.size(); i++) {
		if(m_vNOTs[reverse][i].numgates > 0) {
			std::cout << "Sender values in 1-out-of-" << m_vNOTs[reverse][i].tt_len << " OT" << std::endl;
			for(uint32_t j = 0; j < m_vNOTs[reverse][i].tt_len; j++) {
				std::cout << "X" << j << ": ";
				m_vPreCompOTX[i][j]->PrintHex(0, m_vNOTs[reverse][i].numgates);
			}
		}
	}

	for(uint32_t i = 1; i < m_vPreCompOTC.size(); i++) {
		if(m_vNOTs[reverse][i].numgates > 0) {
			std::cout << "Receiver choices and values in the 1-out-of-" << m_vNOTs[reverse][i].tt_len << " OT" << std::endl;
			std::cout << "C: ";
			m_vPreCompOTC[i]->Print(0, m_vNOTs[reverse][i].numgates * ceil_log2(m_vNOTs[reverse][i].tt_len));
			std::cout << "R: ";
			m_vPreCompOTR[i]->PrintHex(0, m_vNOTs[reverse][i].numgates);
		}
	}
	//}
#endif
	//put the precomputed OT values into m_vPreCompOTMasks
	uint64_t ttlen, outbits, numgates;
	for(uint32_t i = 0; i < m_vPreCompOTX.size(); i++) {
		for(uint32_t j = 0; j < m_vPreCompOTX[i].size(); j++) {
			ttlen = m_vNOTs[!m_bPlaySender][i][j].tt_len;
			outbits = m_vNOTs[!m_bPlaySender][i][j].out_bits;
			numgates = m_vNOTs[!m_bPlaySender][i][j].numgates;
			uint8_t* buf = (uint8_t*) malloc(bits_in_bytes(outbits));
			//m_vPreCompOTMasks[i][j]->Create(numgates * ttlen * outbits);
			for(uint32_t n = 0, ctr = 0; n < numgates; n++) {
				for(uint32_t t = 0; t < ttlen; t++, ctr+=outbits) {//TODO, ctr+=outbits
					//TODO change here to align mask bits
					//for(uint32_t o = 0; o < outbits; o++, ctr++) {
						m_vPreCompOTX[i][j][t]->GetBits(buf, n * outbits, outbits);
						m_vPreCompOTMasks[i][j]->SetBits(buf, ctr, outbits);
						//m_vPreCompOTMasks[i][j]->SetBitNoMask((n * outbits + o) * ttlen + t, m_vPreCompOTX[i][j][t]->GetBitNoMask(n*outbits+o));
					//}
				}
			}
			free(buf);
		}
	}
}

void SetupLUT::PrepareOnlinePhase() {

	//get #in/output bits for other party
	uint32_t insharesndbits = m_cBoolCircuit->GetNumInputBitsForParty(m_eRole);
	uint32_t outsharesndbits = m_cBoolCircuit->GetNumOutputBitsForParty(m_eRole==SERVER ? CLIENT : SERVER);
	uint32_t insharercvbits = m_cBoolCircuit->GetNumInputBitsForParty(m_eRole==SERVER ? CLIENT : SERVER);
	uint32_t outsharercvbits = m_cBoolCircuit->GetNumOutputBitsForParty(m_eRole);

	m_vInputShareSndBuf.Create(insharesndbits, m_cCrypto);

	m_vOutputShareSndBuf.Create(outsharesndbits);
	m_vInputShareRcvBuf.Create(insharercvbits);
	m_vOutputShareRcvBuf.Create(outsharercvbits);

	InitNewLayer();

}


void SetupLUT::EvaluateLocalOperations(uint32_t depth) {
	std::deque<uint32_t> localops = m_cBoolCircuit->GetLocalQueueOnLvl(depth);
	GATE* gate;
#ifdef BENCHBOOLTIME
	timeval tstart, tend;
#endif
	for (uint32_t i = 0; i < localops.size(); i++) {
		gate = &(m_vGates[localops[i]]);
#ifdef DEBUGBOOL_NO_MT
		std::cout << "Evaluating local gate with id = " << localops[i] << " and type " << get_gate_type_name(gate->type) << std::endl;
#endif
		switch (gate->type) {
		case G_LIN:
#ifdef BENCHBOOLTIME
			gettimeofday(&tstart, NULL);
#endif
			EvaluateXORGate(localops[i]);
#ifdef BENCHBOOLTIME
			gettimeofday(&tend, NULL);
			m_nXORTime += getMillies(tstart, tend);
#endif
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
		case G_PRINT_VAL:
			EvaluatePrintValGate(localops[i], C_BOOLEAN);
			break;
		case G_ASSERT:
			EvaluateAssertGate(localops[i], C_BOOLEAN);
			break;
		case G_SHARED_OUT:
			InstantiateGate(gate);
			memcpy(gate->gs.val, m_vGates[gate->ingates.inputs.parent].gs.val, bits_in_bytes(gate->nvals));
			UsedGate(gate->ingates.inputs.parent);
			break;
		case G_SHARED_IN:
			break;
		default:
			if (IsSIMDGate(gate->type)) {
				EvaluateSIMDGate(localops[i]);
			} else {
				std::cerr << "SP-LUT: Non-interactive Operation not recognized: " << (uint32_t) gate->type
						<< "(" << get_gate_type_name(gate->type) << "), stopping execution" << std::endl;
				std::exit(EXIT_FAILURE);
			}
			break;
		}
	}
}




void SetupLUT::EvaluateInteractiveOperations(uint32_t depth) {
	std::deque<uint32_t> interactiveops = m_cBoolCircuit->GetInteractiveQueueOnLvl(depth);

	for (uint32_t i = 0; i < interactiveops.size(); i++) {
		GATE* gate = &(m_vGates[interactiveops[i]]);

#ifdef DEBUG_SPLUT
		std::cout << "Evaluating interactive gate with id = " << interactiveops[i] << " and type " << get_gate_type_name(gate->type) << std::endl;
#endif
		switch (gate->type) {
		case G_NON_LIN:
			//TODO: translate to TT gate with 0001_2
			//SelectiveOpen(interactiveops[i]);
			break;
		case G_NON_LIN_VEC:
			//SelectiveOpenVec(interactiveops[i]);
			break;
		case G_TT:
			EvaluateTTGate(interactiveops[i]);
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
			std::cerr << "BoolNoMTSharing: Interactive Operation not recognized: " << (uint32_t) gate->type
				<< " (" << get_gate_type_name(gate->type) << "), stopping execution" << std::endl;
			std::exit(EXIT_FAILURE);
		}
	}
}

inline void SetupLUT::EvaluateTTGate(uint32_t gateid) {
	//Evaluate Truth Table gate
	GATE* gate = &(m_vGates[gateid]);
	uint32_t* input = gate->ingates.inputs.parents;
	uint32_t nparents = gate->ingates.ningates;
	uint32_t nvals = m_vGates[input[0]].nvals;

	assert(nparents >= 0 && nparents < 32);

	uint32_t table_len = 1<<nparents;
	uint32_t typebitlen = sizeof(UGATE_T) * 8;
	uint32_t outbit_id = m_vOutBitMapping[nparents][gate->gs.tt.noutputs];
	//InstantiateGate(gate);

	if(m_bPlaySender) {
#ifdef DEBUG_SPLUT
		std::cout << "evaluating TT gate as sender, choice rcv ctr = " << m_nChoiceUpdateRcvCtr[nparents][outbit_id]  << std::endl;
#endif
		//in case I am the sender in the underlying OTs; need to update the Xs with the shares of the input gates, which is done later on.
		//Before this, the sender increases the number of updated choice bits that will be received in this stage
		m_nChoiceUpdateRcvCtr[nparents][outbit_id]+=(nvals*nparents);
		//push back gate; assign random values later
		m_vTTGates[nparents].push_back(gateid);
	} else {
#ifdef DEBUG_SPLUT
		std::cout << "evaluating TT gate as receiver, choice snd ctr = " << m_nChoiceUpdateSndCtr[nparents][outbit_id] << std::endl;
#endif
		//in case I am the receiver in the underlying OTs; need to update and send the choices using the shares on the input wires.
		GATE* ingate;
		for(uint32_t i = 0; i < nvals; i++) {
			uint64_t gate_shares = 0;
			uint64_t choice_bits = 0;
			uint32_t ctr = m_nChoiceUpdateSndCtr[nparents][outbit_id];
			//iterate over all parent wires and construct the input gate value
			for(uint32_t j = 0; j < nparents; j++) {
				ingate = &(m_vGates[input[j]]);
				gate_shares |= (((ingate->gs.val[(i/typebitlen)] >> (i%typebitlen)) & 0x01)<<j);
			}

			//get the choice value from the pre-computed OTs
			choice_bits = m_vPreCompOTC[nparents][outbit_id]->Get<uint64_t>(m_vPreCompChoiceIdx[nparents][outbit_id]*nparents+ctr, nparents);
#ifdef DEBUG_SPLUT
			std::cout << "Client parent input shares to gate " << gateid << ": " <<  (hex) << gate_shares << (dec) << std::endl;
#endif
			//std::cout << "Choice inputs: " << (hex) << choice_bits << (dec) << std::endl;
			//XOR the inputs and the choices and send the result to the sender. MOD_SUB can be used to make the sender routine more efficient.
			gate_shares = gate_shares ^ choice_bits;
			//tmpval = MOD_SUB(tmpval, tmpvalb, (1<<nparents)-1);

			//std::cout << "Sending updated choice: " << (hex) << gate_shares << (dec) << std::endl;

			//Write the choice into the buffer that is sent to the sender
			m_vChoiceUpdateSndBuf[nparents][outbit_id]->Set<uint64_t>(gate_shares, ctr, nparents);

			//Increase the counter of sent bits
			m_nChoiceUpdateSndCtr[nparents][outbit_id] += nparents;

		}
#ifdef DEBUG_SPLUT
		std::cout << "Receiver in gate vals: " << std::endl;
		m_vChoiceUpdateSndBuf[nparents]->Print(m_nChoiceUpdateSndCtr[nparents]-(nvals*nparents), m_nChoiceUpdateSndCtr[nparents]);
#endif
		//push back the gate for later use
		m_vTTGates[nparents].push_back(gateid);
		//also indicate that the updated masks that the sender sends in the next step need to be received
		m_nMaskUpdateRcvCtr[nparents][outbit_id] += (nvals * table_len * gate->gs.tt.noutputs);
	}
}


inline void SetupLUT::EvaluateXORGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	uint32_t nvals = gate->nvals;
	uint32_t idleft = gate->ingates.inputs.twin.left;
	uint32_t idright = gate->ingates.inputs.twin.right;
	InstantiateGate(gate);

	for (uint32_t i = 0; i < ceil_divide(nvals, GATE_T_BITS); i++) {
		gate->gs.val[i] = m_vGates[idleft].gs.val[i] ^ m_vGates[idright].gs.val[i];
	}
	//std::cout << "value = " << gate->gs.val[0] << " = " << m_vGates[idleft].gs.val[0] << " ^ " << m_vGates[idright].gs.val[0] << std::endl;

	UsedGate(idleft);
	UsedGate(idright);
}

inline void SetupLUT::EvaluateConstantGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	UGATE_T value = gate->gs.constval;
	InstantiateGate(gate);
	value = value * (m_eRole != CLIENT);

	uint32_t valsize = ceil_divide(gate->nvals, GATE_T_BITS);
	UGATE_T setval;
	if(value == 1L) {
		setval = ~(0L);
	} else {
		setval = 0L;
	}
	for (uint32_t i = 0; i < valsize; ++i) {
		gate->gs.val[i] = setval;
	}
	uint32_t valmod = gate->nvals % GATE_T_BITS;
	if(valmod != 0) {
		gate->gs.val[valsize - 1] &= (1L << valmod) - 1L;
	}
#ifdef DEBUG_SPLUT
		std::cout << "Constant gate value: "<< value << std::endl;
#endif
}


inline void SetupLUT::ShareValues(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	UGATE_T* input = gate->gs.ishare.inval;
	InstantiateGate(gate);

	for (uint32_t i = 0, bitstocopy = gate->nvals, len; i < ceil_divide(gate->nvals, GATE_T_BITS); i++, bitstocopy -= GATE_T_BITS) {
		len = std::min(bitstocopy, (uint32_t) GATE_T_BITS);
		gate->gs.val[i] = m_vInputShareSndBuf.Get<UGATE_T>(m_nInputShareSndSize, len) ^ input[i];
#ifdef DEBUG_SPLUT
		std::cout << (uint32_t) gate->gs.val[i] << " (mine) = " << (uint32_t) m_vInputShareSndBuf.Get<UGATE_T>(m_nInputShareSndSize, len)
				<< " (others) ^ " << (uint32_t) input[i] << " (input)" << std::endl;
#endif
		m_nInputShareSndSize += len;
	}

	free(input);
}

inline void SetupLUT::EvaluateINVGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
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
		gate->gs.val[i] = m_vGates[parentid].gs.val[i] ^ tmpval;
	}
	//set only the remaining nvals%GATE_T_BITS
	if(gate->nvals % GATE_T_BITS != 0) {
		gate->gs.val[i] = (m_vGates[parentid].gs.val[i] ^ tmpval) & (((UGATE_T) 1) << ((gate->nvals % GATE_T_BITS))) - 1;
	}
#ifdef DEBUG_SPLUT
	std::cout << "Evaluated INV gate " << gateid << " with result: " << (hex) << gate->gs.val[0] <<
	" and input: " << m_vGates[parentid].gs.val[0]<< (dec) << std::endl;
#endif
	UsedGate(parentid);
}

inline void SetupLUT::EvaluateCONVGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	uint32_t parentid = gate->ingates.inputs.parents[0];
	if (m_vGates[parentid].context == S_ARITH)
		std::cerr << "can't convert from arithmetic representation directly into Boolean" << std::endl;
	InstantiateGate(gate);

	memset(gate->gs.val, 0, ceil_divide(gate->nvals, 8));
	if (m_eRole == SERVER) {
		for (uint32_t i = 0; i < gate->nvals; i++) {
			gate->gs.val[i / GATE_T_BITS] |= ((uint64_t) m_vGates[parentid].gs.yinput.pi[i]) << (i % GATE_T_BITS);
		}
	} else {
		for (uint32_t i = 0; i < gate->nvals; i++) {
			gate->gs.val[i / GATE_T_BITS] |= ((uint64_t) (m_vGates[parentid].gs.yval[((i + 1) * m_nSecParamBytes) - 1] & 0x01) << (i % GATE_T_BITS));
		}
	}
#ifdef DEBUG_SPLUT
	std::cout << "Set conversion gate value to " << gate->gs.val[0] << std::endl;
#endif

	UsedGate(parentid);
}

inline void SetupLUT::ReconstructValue(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	uint32_t parentid = gate->ingates.inputs.parent;
	assert(m_vGates[parentid].instantiated);
	for (uint32_t i = 0, bitstocopy = gate->nvals, len; i < ceil_divide(gate->nvals, GATE_T_BITS); i++, bitstocopy -= GATE_T_BITS) {
		len = std::min(bitstocopy, (uint32_t) GATE_T_BITS);
#ifdef DEBUG_SPLUT
		std::cout << "m_vOutputShareSndBuf.size = " << m_vOutputShareSndBuf.GetSize() << ", ctr = " <<m_nOutputShareSndSize << ", len = " << len << ", gate->parent = " << parentid
		<< " and val = " << (hex) << m_vGates[parentid].gs.val[i] << (dec) << std::endl;
#endif
		m_vOutputShareSndBuf.Set<UGATE_T>(m_vGates[parentid].gs.val[i], m_nOutputShareSndSize, len);	//gate->gs.val[i], len);
		m_nOutputShareSndSize += len;
	}
	if (gate->gs.oshare.dst != ALL)
		UsedGate(parentid);
}


void SetupLUT::FinishCircuitLayer() {
	//Compute the values of the AND gates
#ifdef DEBUGBOOL_NO_MT
	if(m_nInputShareRcvSize > 0) {
		std::cout << "Received "<< m_nInputShareRcvSize << " input shares: ";
		m_vInputShareRcvBuf.Print(0, m_nInputShareRcvSize);
	}
	if(m_nOutputShareRcvSize > 0) {
		std::cout << "Received " << m_nOutputShareRcvSize << " output shares: ";
		m_vOutputShareRcvBuf.Print(0, m_nOutputShareRcvSize);
	}
#endif

	//EvaluateMTs();
	//EvaluateANDGate();
	if(m_bPlaySender) {
#ifdef DEBUG_SPLUT
		std::cout << "Setting TT gate as sender" << std::endl;
#endif
		SenderEvaluateTTGates();
	} else {
#ifdef DEBUG_SPLUT
		std::cout << "Setting TT gate as sender" << std::endl;
#endif
		ReceiverEvaluateTTGates();
	}
	AssignInputShares();
	AssignOutputShares();

	InitNewLayer();
	//Role switching
	m_bPlaySender = !m_bPlaySender;

}



/*
 * This routine assigns a random masks to the TT gate, takes the updated choice bits from the receiver,
 *  computes the updated OTs and prepares them for sending
 */
void SetupLUT::SenderEvaluateTTGates() {
	uint64_t* ttable;
	uint32_t len, choicelen, nvals;
	uint64_t gate_mask, updated_choice, tmp_table, parents_value, tmp_pre_mask;
	//uint64_t tmpmaskidx;
	uint32_t typebitlen = sizeof(uint64_t) * 8;
	timespec t_start, t_end;
	clock_gettime(CLOCK_MONOTONIC, &t_start);

	for(uint32_t i = 0; i < m_vTTGates.size(); i++) {
		//bit-length of the masks that are transferred
		len = m_vNOTs[0][i][0].tt_len;
		//bit-length of the choices
		choicelen = ceil_log2(len);
		//a counter for the starting position of differently sized tables
		std::vector<uint32_t> ctr_idx(m_vOutBitMapping[i].size(), 0);

		for(uint32_t g = 0; g < m_vTTGates[i].size(); g++) {
			GATE* gate = &(m_vGates[m_vTTGates[i][g]]);
			ttable = gate->gs.tt.table;


			//assert(gate->nvals < 65);
			uint32_t* input = gate->ingates.inputs.parents;
			uint32_t nparents = gate->ingates.ningates;
			uint32_t out_bits = gate->gs.tt.noutputs;
			nvals = gate->nvals / out_bits;

			//Get the id of the mapping from #output bits to address for masks
			uint32_t outs_id = m_vOutBitMapping[nparents][out_bits];

			//Attach the table to a cbitvector to access bits individually
			CBitVector tab_vec;
			tab_vec.AttachBuf((BYTE*) ttable, ceil_divide(len * out_bits, 8));


#ifdef DEBUG_SPLUT
			std::cout << "Received Choices: ";
			m_vChoiceUpdateRcvBuf[i][outs_id]->PrintHex(0, m_vTTGates[i].size()*choicelen);
#endif

			//First step: instantiate gate and assign random masks to it
			InstantiateGate(gate);
			m_vTableRnd[i][outs_id]->GetBits((uint8_t*) gate->gs.val, m_nTableRndIdx[i][outs_id], gate->nvals);
			m_nTableRndIdx[i][outs_id] += (gate->nvals);

#ifdef DEBUG_SPLUT
			std::cout << "Sender Gate " << m_vTTGates[i][g] << " set to: ";
			for(uint32_t j = 0; j < ceil_divide(gate->nvals, typebitlen); j++) {
				std::cout << (hex) << (uint64_t) gate->gs.val[j] << (dec);
			}nvals, GATE_T_BITS
			std::cout << std::endl;
#endif

			//Second step: update the pre-computed masks using the table and prepare the answers
			for(uint32_t n = 0; n < nvals; n++, ctr_idx[outs_id] += choicelen) {
				updated_choice = m_vChoiceUpdateRcvBuf[i][outs_id]->Get<uint64_t>(ctr_idx[outs_id], choicelen);
				parents_value = 0;
				//std::cout << "Sender getting mask " << tmpmaskidx << std::endl;
				for(uint32_t j = 0; j < nparents; j++) {
					parents_value ^= (((m_vGates[input[j]].gs.val[n/typebitlen] >> (n%typebitlen)) & 0x01) << j);
				}

				//get the correct random mask bits that were assigned to the gate
				gate_mask = 0;
				for(uint32_t o = 0; o < out_bits; o++) {
					gate_mask |= (((gate->gs.val[(n+(o*nvals))/typebitlen] >> ((n+(o*nvals))%typebitlen)) & 0x01) << o);
				}

				//std::cout << "Server parent input shares to gate " << m_vTTGates[i][g] << ": " <<  (hex) << parents_value << (dec) << std::endl;
				//std::cout << "Updated choice input: " << (hex) << updated_choice << (dec) << std::endl;

#ifdef DEBUG_SPLUT
				std::cout << "Server parent input shares to gate " << m_vTTGates[i][g] << ": " <<  (hex) << parents_value <<
						", receiver choice = " << updated_choice << (dec) << std::endl;
#endif

				//todo: only supports up to 64 out_bits, replace by Byte* once this is working correctly
				for(uint32_t t = 0; t < len; t++) {
					//Get the bits from the pre-computed OT
					tmp_pre_mask = m_vPreCompOTX[i][outs_id][updated_choice^t]->Get<uint64_t>(m_vPreCompMaskIdx[i][outs_id], out_bits);
					//Get the truth table bits
					tmp_table = tab_vec.Get<uint64_t>((parents_value^t) * out_bits, out_bits);
					//Compute the XOR of all values
					tmp_pre_mask = gate_mask ^ tmp_pre_mask ^ tmp_table;
					//Put the resulting value into the send buffer, which is transmitted to the client at the end of this round
					m_vMaskUpdateSndBuf[i][outs_id]->Set(tmp_pre_mask, m_nMaskUpdateSndCtr[i][outs_id] + (updated_choice^t) * out_bits, out_bits);
				}
				m_vPreCompMaskIdx[i][outs_id]+=out_bits;
				m_nMaskUpdateSndCtr[i][outs_id]+=(len*out_bits);
			}

			//std::cout << "Server Obtained gate result: " << gate->gs.val[0] << std::endl;
			for(uint32_t j = 0; j < nparents; j++) {
				UsedGate(input[j]);
			}
			tab_vec.DetachBuf();

			free(ttable);
			free(input);
		}
		m_vTTGates[i].clear();
	}
	clock_gettime(CLOCK_MONOTONIC, &t_end);
	t_snd += getMillies(t_start, t_end);
	//std::cout << "TT Sender time: " << t_snd << std::endl;
}


/* TODO: The following code is an optimization for the online phase of SP-LUT but is currently deactivated since it does not work properly!
 * void clshift(uint64_t* buf, uint32_t bufbits, uint32_t pos, uint64_t* tmpbuf) {
	uint32_t idxshift = pos >> 6;
	uint32_t posshift = pos & 0x3F;

	uint32_t inv_posshift = 64-posshift;
	uint64_t upper_mask = ((1L<<posshift)-1)<<inv_posshift;
	uint32_t bufbytes = (bufbits + 1) / 8;
	uint32_t bufiters = bufbytes / sizeof(uint64_t);

	memcpy(tmpbuf, buf, bufbytes);
	memcpy(tmpbuf+bufiters, buf, bufbytes);

	memset(buf, 0, bufbytes);

	for(uint32_t i = 0, ibuf=bufiters; i < bufiters; i++,ibuf++) {
		//put the lower half on
		buf[i] |= ((tmpbuf[ibuf-idxshift-1] & upper_mask) >> inv_posshift);
		//put the upper half on
		buf[i] |= (tmpbuf[ibuf-idxshift] << posshift);
	}
}


void crshift(uint64_t* buf, uint32_t bufbits, uint32_t pos, uint64_t* tmpbuf) {
	uint32_t idxshift = pos >> 6;
	uint32_t posshift = pos & 0x3F;

	uint32_t inv_posshift = 64-posshift;
	uint64_t lower_mask = ((1L<<posshift)-1);
	uint32_t bufbytes = (bufbits + 1) / 8;
	uint32_t bufiters = bufbytes / sizeof(uint64_t);

	memcpy(tmpbuf, buf, bufbytes);
	memcpy(tmpbuf+bufiters, buf, bufbytes);

	memset(buf, 0, bufbytes);


	for(uint32_t i = 0; i < bufiters; i++) {
		//put the lower half on
		buf[i] |= (tmpbuf[i+idxshift] >> posshift);
		//put the upper half on
		buf[i] |= ((tmpbuf[i+idxshift+1] & lower_mask) << inv_posshift);
	}
}


void SetupLUT::SenderEvaluateTTGates() {
	uint64_t* ttable;
	uint32_t len, choicelen, nvals;
	uint64_t tmp_mask, tmp_choice, tmpmaskidx, tmp_table, tmp_val, tmp_pre_mask, tmp_mod;
	uint32_t typebitlen = sizeof(uint64_t) * 8;
	timespec t_start, t_end;
	clock_gettime(CLOCK_MONOTONIC, &t_start);
	uint64_t* gateval_buf = (uint64_t*) malloc(MAX_GATEVAL_BUFSIZE);


	for(uint32_t i = 0; i < m_vTTGates.size(); i++) {
		len = m_vNOTs[0][i][0].tt_len;
		choicelen = ceil_log2(len);
		std::vector<uint32_t> c_idx(m_vOutBitMapping[i].size(), 0);
		//assert(len == (1<<choicelen));
		//std::cout << "choicelen = " << choicelen << ", i = " << i << std::endl;
		//assert(choicelen == i);
		tmp_mod = 1<<choicelen;

		uint8_t* mytable = (uint8_t*) calloc(256, sizeof(uint8_t)); //TODO: static at the moment!, replace by: (uint8_t*) calloc(len, sizeof(uint8_t));
		uint8_t* mytable_tmp = (uint8_t*) calloc(512, sizeof(uint8_t));//TODO: static at the moment!, replace by (uint8_t*) calloc(2*len, sizeof(uint8_t));

		for(uint32_t g = 0; g < m_vTTGates[i].size(); g++) {
			GATE* gate = &(m_vGates[m_vTTGates[i][g]]);
			ttable = gate->gs.tt.table;

			//assert(gate->nvals < 65);
			uint32_t* input = gate->ingates.inputs.parents;
			uint32_t nparents = gate->ingates.ningates;
			uint32_t out_bits = gate->gs.tt.noutputs;
			nvals = gate->nvals / out_bits;

			uint32_t outs_id = m_vOutBitMapping[nparents][out_bits];

#ifdef DEBUGBOOL_NO_MT
			std::cout << "Received Choices: ";
			m_vChoiceUpdateRcvBuf[i][outs_id]->PrintHex(0, m_vTTGates[i].size()*choicelen);
#endif

			//TODO can not handle nvals > 64 yet. Use byte* for tmp_mask instead routine
			//First step: instantiate gate and assign random masks to it
			InstantiateGate(gate);
			m_vTableRnd[i][outs_id]->GetBits((uint8_t*) gate->gs.val, m_nTableRndIdx[i][outs_id], gate->nvals);
			m_nTableRndIdx[i][outs_id] += (gate->nvals);

#ifdef DEBUGBOOL_NO_MT
			std::cout << "Sender Gate " << m_vTTGates[i][g] << " set to: ";
			for(uint32_t j = 0; j < ceil_divide(gate->nvals, typebitlen); j++) {
				std::cout << (hex) << (uint64_t) gate->gs.val[j] << (dec);
			}
			std::cout << std::endl;
#endif

			if((m_vPreCompMaskIdx[i][outs_id] & 0x03) == 0) {
				m_vMaskUpdateSndBuf[i][outs_id]->SetBits(m_vPreCompOTMasks[i][outs_id]->GetArr()+bits_in_bytes(m_vPreCompMaskIdx[i][outs_id]),
					(uint64_t) m_nMaskUpdateSndCtr[i][outs_id], (uint64_t) len * out_bits * nvals);
			} else {
				m_vMaskUpdateSndBuf[i][outs_id]->SetBitsPosOffset(m_vPreCompOTMasks[i][outs_id]->GetArr()+bits_in_bytes(m_vPreCompMaskIdx[i][outs_id]),
						m_vPreCompMaskIdx[i][outs_id]%8, (uint64_t) m_nMaskUpdateSndCtr[i][outs_id], (uint64_t) len * out_bits * nvals);
			}

			//Second step: update the pre-computed masks using the table and prepare the answers
			for(uint32_t n = 0; n < nvals; n++, c_idx[outs_id] += choicelen) {
				tmp_choice = m_vChoiceUpdateRcvBuf[i][outs_id]->Get<uint64_t>(c_idx[outs_id], choicelen);
				tmp_val = 0;
				//std::cout << "Sender getting mask " << tmpmaskidx << std::endl;
				for(uint32_t j = 0; j < nparents; j++) {
					tmp_val ^= (((m_vGates[input[j]].gs.val[n/typebitlen] >> (n%typebitlen)) & 0x01) << j);
				}

				//TODO: extend to arbitrary length outbits. currently capped to 64 outbits
				//uint64_t gateval = 0;

				uint32_t iters = ceil_divide(out_bits * len, sizeof(uint64_t) * 8);
				//std::cout << out_bits * len << ", " << (sizeof(uint64_t) * 8) << std::endl;
				memset(gateval_buf, 0, MAX_GATEVAL_BUFSIZE);
				for(uint32_t o = 0; o < out_bits; o++) {
					//gateval |= (((gate->gs.val[(n+(o*nvals))/typebitlen] >> ((n+(o*nvals))%typebitlen)) & 0x01) << o);
					if(((gate->gs.val[(n+(o*nvals))/typebitlen] >> ((n+(o*nvals))%typebitlen)) & 0x01)) {
						for(uint32_t p = 0; p < iters; p++) {
							//std::cout << (hex) << gateval_buf[p] << " ^ " << gateval_masks[out_bits-1][o][p];;
							gateval_buf[p] ^= gateval_masks[out_bits-1][o][p];
							//std::cout << " = " << gateval_buf[p] << (dec) << std::endl;
						}
					}
				}
//				std::cout << "gateval = " << (hex) << gateval << (dec) << std::endl;
//				std::cout << "gatebuf = ";
//				for(uint32_t p = 0; p < iters; p++) {
//					std::cout << (hex) << gateval_buf[p] << (dec) << ", ";
//				}
//				std::cout << std::endl;

				//std::cout << "Server input gates = " << (hex) << tmp_val << (dec) << std::endl;
				uint64_t* tableptr = ttable;
#ifdef DEBUGBOOL_NO_MT
				std::cout << "Sender value = " << tmp_val << ", receiver choice = " << tmp_choice << std::endl;
				std::cout << "iterating over masks: " << std::endl;
#endif
				tmpmaskidx = m_vPreCompMaskIdx[i][outs_id];

				//std::cout << "going to process this table entries:" << std::endl;

				uint32_t table_perm = (tmp_val >> 4) & 0x0F;
				uint32_t entry_perm = (tmp_val) & 0x0F;

//				for(uint32_t p = 0; p < 16; p++) {
//					std::cout << (hex) << ((uint64_t*)aes_sbox_multi_seq_perm_out_ttable[p])[2*entry_perm] << ", " <<
//							((uint64_t*)aes_sbox_multi_seq_perm_out_ttable[p])[2*entry_perm+1] << (dec) << std::endl;
//				}

				for(uint32_t p = 0; p < 16; p++) {
					memcpy(mytable+p*16, (uint8_t*) (((uint64_t*)aes_sbox_multi_seq_perm_out_ttable[table_perm^p])+2*entry_perm), 16);
				}

				//TODO: currently not suited for arbitrary shifts. Most of the occurring cases should be covered
				assert((len * out_bits > 64 && ((len * out_bits) & 0x3F) == 0) || len * out_bits < 64);
				//std::cout << "tmp_choice = " << tmp_choice << ", shifting by " << tmp_choice * 8 << " positions" << std::endl;
				crshift((uint64_t*) mytable, len * out_bits, tmp_choice*out_bits, (uint64_t*) mytable_tmp);

				//for(uint32_t p = 0; p < len; p++) {
					//mytable_tmp[p] = mytable[(p+tmp_choice)&(tmp_mod-1)] ^ gateval;
				//	mytable[p] = mytable[p] ^ gateval;
					//m_vMaskUpdateSndBuf[i][outs_id]->XOR<uint64_t>(gateval, m_nMaskUpdateSndCtr[i][outs_id]+p*out_bits, out_bits);
				//}
				//mytable = mytable_tmp;

				//std::cout << "tmp_choice = " <<  tmp_choice << ", tmp_val = " << tmp_val << ", offset = " << (tmp_choice ^ tmp_val) << std::endl;
				//uint8_t* tableval = (uint8_t*) calloc(len, sizeof(uint8_t));

				m_vMaskUpdateSndBuf[i][outs_id]->XORBits(mytable, m_nMaskUpdateSndCtr[i][outs_id], out_bits*len);
				m_vMaskUpdateSndBuf[i][outs_id]->XORBits((uint8_t*) gateval_buf, m_nMaskUpdateSndCtr[i][outs_id], out_bits*len);
				//for(uint32_t t = 0, posidx=tmp_choice; t < len; t++, posidx=(posidx+1)&(tmp_mod-1)) {
				//for(uint32_t t = 0; t < len; t++) {
					//tmp_pre_mask = m_vPreCompOTMasks[i][outs_id]->Get<uint64_t>(tmpmaskidx + t * out_bits, out_bits);
					//uint64_t bla = m_vMaskUpdateSndBuf[i][outs_id]->Get<uint64_t>(m_nMaskUpdateSndCtr[i][outs_id] + t * out_bits, out_bits);
					//assert(tmp_pre_mask == bla);
					//std::cout << tmpmaskidx << ", " << m_nMaskUpdateSndCtr[i][outs_id] << ": tmp_pre_mask = " << tmp_pre_mask << ", mask buf = " << bla << std::endl;

//					tmp_table = 0;
//
//					for(uint32_t o = 0; o < out_bits; o++) {
//						//uint32_t id = (tmp_val^t) + o * len;
//						//tmp_table |= (((tableptr[id/typebitlen]>>(id%typebitlen)) & 0x01) << o);
//						uint32_t id = (tmp_val^posidx) * out_bits + o;
//						tmp_table |= (((tableptr[id/typebitlen]>>(id%typebitlen)) & 0x01) << o);
//					}
//					tableval[t] = tmp_table;

					//std::cout << t << ": " << (tmp_val^posidx) << std::endl;

					//std::cout << "table val = " << (hex) << tmp_table  << (dec) << std::endl;
					//tmp_mask = gateval;//^tmp_pre_mask;
					//m_vMaskUpdateSndBuf[i][outs_id]->XOR<uint64_t>(tmp_mask, m_nMaskUpdateSndCtr[i][outs_id] + t * out_bits, out_bits);
#ifdef DEBUGBOOL_NO_MT
						std::cout << "For t = " << t << ", pos " << (tmp_choice+t)%tmp_mod << " send = " << (hex) << tmp_mask << ", table = " << tmp_table << " (tid = " << (tmp_val^t) <<
								"), gval = " << gateval << ", precomp OT = " << tmp_pre_mask << (dec) << std::endl;
#endif


#ifdef DEBUGBOOL_NO_MT
					std::cout << "Mask Buf sent: " << std::endl;
					m_vMaskUpdateSndBuf[i][outs_id]->PrintHex(bits_in_bytes(m_nMaskUpdateSndCtr[i][outs_id]), bits_in_bytes(m_nMaskUpdateSndCtr[i][outs_id]+len));
#endif
				//}
//				std::cout << "processed table:" << std::endl;
//				for(uint32_t p = 0; p < 16; p++) {
//					std::cout << (hex) << ((uint64_t*)tableval)[2*p] << ", " <<
//							((uint64_t*)tableval)[2*p+1] << (dec) << std::endl;
//				}
//				std::cout << "my table:" << std::endl;
//				for(uint32_t p = 0; p < 16; p++) {
//					std::cout << (hex) << ((uint64_t*)mytable)[2*p] << ", " <<
//							((uint64_t*)mytable)[2*p+1] << (dec) << std::endl;
//				}
				m_nMaskUpdateSndCtr[i][outs_id]+=(out_bits * len);
				m_vPreCompMaskIdx[i][outs_id]+=(out_bits * len);

			}
			//std::cout << "Server Obtained gate result: " << gate->gs.val[0] << std::endl;
			for(uint32_t j = 0; j < nparents; j++) {
				UsedGate(input[j]);
			}
			free(ttable);
			free(input);
		}
		m_vTTGates[i].clear();
		free(mytable);
		free(mytable_tmp);
	}
	//free(gateval_buf);
	clock_gettime(CLOCK_MONOTONIC, &t_end);
	t_snd += getMillies(t_start, t_end);
	//std::cout << "TT Sender time: " << t_snd << std::endl;
}
*/


/*
 * This routine unmasks the updated masks and assigns them to the TT gate
 */
void SetupLUT::ReceiverEvaluateTTGates() {
	uint32_t len, choicelen;
	uint64_t tmp_choice, tmp_rcv;
	uint32_t typebitlen = sizeof(uint64_t) * 8;
	timespec t_start, t_end;
	clock_gettime(CLOCK_MONOTONIC, &t_start);

	for(uint32_t i = 0; i < m_vTTGates.size(); i++) {
		//bit-length of the truth table
		len = m_vNOTs[0][i][0].tt_len;
		//bit length of the choices
		choicelen = ceil_log2(len);
		//stores the addresses for truth tables with different numbers of output bits
		std::vector<uint32_t> rcvbufaddr(m_vOutBitMapping[i].size(), 0);

		for(uint32_t g = 0; g < m_vTTGates[i].size(); g++) {
			GATE* gate = &(m_vGates[m_vTTGates[i][g]]);
			uint32_t* input = gate->ingates.inputs.parents;
			uint32_t nparents = gate->ingates.ningates;

			uint64_t* ttable = gate->gs.tt.table;

			uint32_t out_bits = gate->gs.tt.noutputs;
			uint32_t nvals = gate->nvals / out_bits;

			uint32_t outs_id = m_vOutBitMapping[nparents][out_bits];

			InstantiateGate(gate);

			//Form the choice from the input values
			for(uint32_t n = 0; n < nvals; n++) {
				//std::cout << "Receiver getting choices bits " << m_vPreCompChoiceIdx[i] << std::endl;
#ifdef DEBUGBOOL_NO_MT
				std::cout << "Mask Buf received: " << std::endl;
				m_vMaskUpdateRcvBuf[i][outs_id]->PrintHex(bits_in_bytes(rcvbufaddr[outs_id]), bits_in_bytes(rcvbufaddr[outs_id]+out_bits*len));
#endif
				tmp_choice = m_vPreCompOTC[i][outs_id]->Get<uint64_t>(m_vPreCompChoiceIdx[i][outs_id] * choicelen, choicelen);
#ifdef DEBUG_SPLUT
				std::cout << "Receiver choosing value " << tmp_choice << ", adding len = " << len << std::endl;
#endif

#ifdef SEQ_OUTBITS
				for(uint32_t o = 0; o < out_bits; o++) {
					//Obtain the updated mask that the choice corresponds to and XOR it with the pre-computed mask
					tmp_rcv = m_vMaskUpdateRcvBuf[i][outs_id]->Get<uint64_t>(rcvbufaddr[outs_id] + tmp_choice, 1);

					tmp_rcv = tmp_rcv ^ m_vPreCompOTR[i][outs_id]->Get<uint64_t>((m_vPreCompChoiceIdx[i][outs_id]*out_bits)+o, 1);
					rcvbufaddr[outs_id]+=len;
#ifdef DEBUGBOOL_NO_MT
					std::cout << "Obtained result " << tmp_rcv << std::endl;
#endif
					gate->gs.val[(n+(o*nvals))/typebitlen] = gate->gs.val[(n+(o*nvals))/typebitlen] ^ (tmp_rcv << ((n+(o*nvals))%typebitlen));
				}
				m_vPreCompChoiceIdx[i][outs_id]++;
#else
				tmp_rcv = m_vMaskUpdateRcvBuf[i][outs_id]->Get<uint64_t>(rcvbufaddr[outs_id] + tmp_choice*out_bits, out_bits);
#ifdef DEBUG_SPLUT
				std::cout << "Value from mask buf = " << (hex) << tmp_rcv << ", precomp OT = " <<
						m_vPreCompOTR[i][outs_id]->Get<uint64_t>((m_vPreCompChoiceIdx[i][outs_id]*out_bits), out_bits) << (dec) << std::endl;
#endif
				tmp_rcv = tmp_rcv ^ m_vPreCompOTR[i][outs_id]->Get<uint64_t>((m_vPreCompChoiceIdx[i][outs_id]*out_bits), out_bits);
				rcvbufaddr[outs_id]+=(out_bits * len);
				for(uint32_t o = 0; o < out_bits; o++) {
					gate->gs.val[(n+(o*nvals))/typebitlen] = gate->gs.val[(n+(o*nvals))/typebitlen] ^ (((tmp_rcv>>o)&0x01) << ((n+(o*nvals))%typebitlen));
				}
				m_vPreCompChoiceIdx[i][outs_id]++;
#endif
			}
#ifdef DEBUG_SPLUT
			std::cout << "Receiver Gate " << m_vTTGates[i][g] << " set to: ";
			for(uint32_t j = 0; j < ceil_divide(gate->nvals, typebitlen); j++) {
				std::cout << (uint64_t) gate->gs.val[j] << (dec);
			}
			std::cout << std::endl;
#endif
			for(uint32_t j = 0; j < nparents; j++) {
				UsedGate(input[j]);
			}

			free(ttable);
			free(input);
		}
		m_vTTGates[i].clear();
	}
	clock_gettime(CLOCK_MONOTONIC, &t_end);
	t_rcv += getMillies(t_start, t_end);
	//std::cout << "TT Receiver time: " << t_rcv << std::endl;
}


void SetupLUT::AssignInputShares() {
	GATE* gate;
	for (uint32_t i = 0, j, rcvshareidx = 0, bitstocopy, len; i < m_vInputShareGates.size(); i++) {
		gate = &(m_vGates[m_vInputShareGates[i]]);
		InstantiateGate(gate);

		bitstocopy = gate->nvals;
		for (j = 0; j < ceil_divide(gate->nvals, GATE_T_BITS); j++, bitstocopy -= GATE_T_BITS) {
			len = std::min(bitstocopy, (uint32_t) GATE_T_BITS);
			gate->gs.val[j] = m_vInputShareRcvBuf.Get<UGATE_T>(rcvshareidx, len);
#ifdef DEBUG_SPLUT
			std::cout << "assigned value " << gate->gs.val[j] << " to gate " << m_vInputShareGates[i] << " with nvals = " << gate->nvals << " and sharebitlen = " << gate->sharebitlen << std::endl;
#endif
			rcvshareidx += len;
		}
	}
}

void SetupLUT::AssignOutputShares() {
	GATE* gate;
	for (uint32_t i = 0, j, rcvshareidx = 0, bitstocopy, len, parentid; i < m_vOutputShareGates.size(); i++) {
		gate = &(m_vGates[m_vOutputShareGates[i]]);
		parentid = gate->ingates.inputs.parent;
		InstantiateGate(gate);

		bitstocopy = gate->nvals;
		for (j = 0; j < ceil_divide(gate->nvals, GATE_T_BITS); j++, bitstocopy -= GATE_T_BITS) {
			len = std::min(bitstocopy, (uint32_t) GATE_T_BITS);
			gate->gs.val[j] = m_vGates[parentid].gs.val[j] ^ m_vOutputShareRcvBuf.Get<UGATE_T>(rcvshareidx, len);
#ifdef DEBUG_SPLUT
			std::cout << "Outshare: " << (hex) << gate->gs.val[j] << " = " << m_vGates[parentid].gs.val[j] << " (mine) ^ " <<
					m_vOutputShareRcvBuf.Get<UGATE_T>(rcvshareidx, len) << " (others)" << (dec) << std::endl;
#endif
			rcvshareidx += len;
		}
		UsedGate(parentid);
	}
}

void SetupLUT::GetDataToSend(std::vector<BYTE*>& sendbuf, std::vector<uint64_t>& sndbytes) {
	//the receiver XORs the precomputed masks on top
	/*if(!m_bPlaySender) {
		for(uint32_t i = 0; i < m_nChoiceUpdateSndCtr.size(); i++) {
			for(uint32_t j = 0; j < m_nChoiceUpdateSndCtr[i].size(); j++) {
				uint32_t choicecodelen = i;
				if(m_nChoiceUpdateSndCtr[i][j] > 0) {
#ifdef DEBUGBOOL_NO_MT
					std::cout << "Orig Choice buffer =\t";
					m_vChoiceUpdateSndBuf[i][j]->Print(0, m_nChoiceUpdateSndCtr[i][j]);
					std::cout << "PreCompChoice buffer =\t";
					m_vPreCompOTC[i][j]->Print(0, m_nChoiceUpdateSndCtr[i][j]);
#endif
					m_vChoiceUpdateSndBuf[i][j]->XORBitsPosOffset(m_vPreCompOTC[i][j]->GetArr(),
							m_vPreCompChoiceIdx[i][j]*choicecodelen, 0, m_nChoiceUpdateSndCtr[i][j]);
#ifdef DEBUGBOOL_NO_MT
					std::cout << "Updated Choice buffer =\t";
					m_vChoiceUpdateS
					SndBuf[i]->Print(0, m_nChoiceUpdateSndCtr[i][j]);
#endif
				}
			}
		}
	}*/

	//the receiver sends his values directly, the server is allowed to stash its messages
	if(!m_bPlaySender) {
		//pass on what is still on the stash
		for(uint32_t i = 0; i < m_vSndBufStash.size(); i++) {
#ifdef DEBUG_SPLUT
			std::cout << "pushing stash with " << m_vSndBytesStash[i] << " byte size" << std::endl;
#endif
			sendbuf.push_back(m_vSndBufStash[i]);
			sndbytes.push_back(m_vSndBytesStash[i]);
		}
		for(uint32_t i = 0; i < m_nMaskUpdateSndCtr.size(); i++) {
			for(uint32_t j = 0; j < m_nMaskUpdateSndCtr[i].size(); j++) {
				if(m_nMaskUpdateSndCtr[i][j] > 0) {
#ifdef DEBUG_SPLUT
					std::cerr << "sending masks of " << ceil_divide(m_nMaskUpdateSndCtr[i][j], 8) << " byte size " << std::endl;
#endif
					//exit(0);
					sendbuf.push_back(m_vMaskUpdateSndBuf[i][j]->GetArr());
					sndbytes.push_back(ceil_divide(m_nMaskUpdateSndCtr[i][j], 8));
					//	m_vPreCompMaskIdx[i] += m_nChoiceUpdateSndCtr[i];
					m_nMaskUpdateSndCtr[i][j] = 0;
					//m_vMaskUpdateSndBuf[i]->Reset();
				}
			}
		}

		//Input shares
		if (m_nInputShareSndSize > 0) {
#ifdef DEBUG_SPLUT
			std::cout << "sending input of size " << ceil_divide(m_nInputShareSndSize, 8) << " bytes" << std::endl;
#endif
			sendbuf.push_back(m_vInputShareSndBuf.GetArr());
			sndbytes.push_back(ceil_divide(m_nInputShareSndSize, 8));
		}

		//Output shares
		if (m_nOutputShareSndSize > 0) {
#ifdef DEBUG_SPLUT
			std::cout << "sending output of size " << ceil_divide(m_nOutputShareSndSize, 8) << " bytes" << std::endl;
#endif
			sendbuf.push_back(m_vOutputShareSndBuf.GetArr());
			sndbytes.push_back(ceil_divide(m_nOutputShareSndSize, 8));
		}

		for(uint32_t i = 0; i < m_vChoiceUpdateSndBuf.size(); i++) {
			for(uint32_t j = 0; j < m_vChoiceUpdateSndBuf[i].size(); j++) {
				if(m_nChoiceUpdateSndCtr[i][j] > 0) {
#ifdef DEBUG_SPLUT
				std::cout << "sending choices of size " << ceil_divide(m_nChoiceUpdateSndCtr[i][j], 8) << " bytes " << std::endl;
#endif
					sendbuf.push_back(m_vChoiceUpdateSndBuf[i][j]->GetArr());
					sndbytes.push_back(ceil_divide(m_nChoiceUpdateSndCtr[i][j], 8));
				}
			}

		}
	} else {
		//stash changes and prepare for next round
		//stash input shares
		uint64_t tmpbuf_bytes;
		uint8_t* tmpbuf;

		if (m_nInputShareSndSize > 0) {
			tmpbuf_bytes = ceil_divide(m_nInputShareSndSize, 8);
#ifdef DEBUG_SPLUT
			std::cout << "stashing input of size " << tmpbuf_bytes << " bytes" << std::endl;
#endif
			tmpbuf = (uint8_t*) malloc(tmpbuf_bytes);
			memcpy(tmpbuf, m_vInputShareSndBuf.GetArr(), tmpbuf_bytes);
			m_vSndBufStash.push_back(tmpbuf);
			m_vSndBytesStash.push_back(tmpbuf_bytes);
		}

		//stash output shares
		if (m_nOutputShareSndSize > 0) {
			tmpbuf_bytes = ceil_divide(m_nOutputShareSndSize, 8);
#ifdef DEBUG_SPLUT
			std::cout << "stashing output of size " << tmpbuf_bytes << " bytes" << std::endl;
#endif
			tmpbuf = (uint8_t*) malloc(tmpbuf_bytes);
			memcpy(tmpbuf, m_vOutputShareSndBuf.GetArr(), tmpbuf_bytes);
			m_vSndBufStash.push_back(tmpbuf);
			m_vSndBytesStash.push_back(tmpbuf_bytes);
		}

		//stash table updates
		for(uint32_t i = 0; i < m_nMaskUpdateSndCtr.size(); i++) {
			for(uint32_t j = 0; j < m_nMaskUpdateSndCtr[i].size(); j++) {
				if(m_nChoiceUpdateSndCtr[i][j] > 0) {
					std::cerr << "Choices should not be stashed; Something is wrong here. Exiting!" << std::endl;
					std::exit(EXIT_FAILURE);
				}
				if(m_nMaskUpdateSndCtr[i][j] > 0) {
					tmpbuf_bytes = ceil_divide(m_nMaskUpdateSndCtr[i][j], 8);
#ifdef DEBUG_SPLUT
					std::cout << "stashing masks of size " << tmpbuf_bytes << " bytes" << std::endl;
#endif
					tmpbuf = (uint8_t*) malloc(tmpbuf_bytes);
					memcpy(tmpbuf, m_vMaskUpdateSndBuf[i][j]->GetArr(), tmpbuf_bytes);
					m_vSndBufStash.push_back(tmpbuf);
					m_vSndBytesStash.push_back(tmpbuf_bytes);
				}
			}
		}
	}

#ifdef DEBUG_SPLUT
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


void SetupLUT::GetBuffersToReceive(std::vector<BYTE*>& rcvbuf, std::vector<uint64_t>& rcvbytes) {
	//Input shares
	if (m_nInputShareRcvSize > 0) {
#ifdef DEBUG_SPLUT
		std::cout << "want to receive input of size " << ceil_divide(m_nInputShareRcvSize, 8) << " bytes" << std::endl;
#endif
		if (m_vInputShareRcvBuf.GetSize() < ceil_divide(m_nInputShareRcvSize, 8)) {
			m_vInputShareRcvBuf.ResizeinBytes(ceil_divide(m_nInputShareRcvSize, 8));
		}
		rcvbuf.push_back(m_vInputShareRcvBuf.GetArr());
		rcvbytes.push_back(ceil_divide(m_nInputShareRcvSize, 8));
	}

	//Output shares
	if (m_nOutputShareRcvSize > 0) {
#ifdef DEBUG_SPLUT
		std::cout << "want to receive output of size " << ceil_divide(m_nOutputShareRcvSize, 8) << " bytes " << std::endl;
#endif
		if (m_vOutputShareRcvBuf.GetSize() < ceil_divide(m_nOutputShareRcvSize, 8)) {
			m_vOutputShareRcvBuf.ResizeinBytes(ceil_divide(m_nOutputShareRcvSize, 8));
		}
		rcvbuf.push_back(m_vOutputShareRcvBuf.GetArr());
		rcvbytes.push_back(ceil_divide(m_nOutputShareRcvSize, 8));
	}

	for(uint32_t i = 0; i < m_vChoiceUpdateRcvBuf.size(); i++) {
		for(uint32_t j = 0; j < m_vChoiceUpdateRcvBuf[i].size(); j++) {
			if(m_nChoiceUpdateRcvCtr[i][j] > 0) {
#ifdef DEBUG_SPLUT
			std::cout << "want to receive choices of size " << ceil_divide(m_nChoiceUpdateRcvCtr[i][j], 8) << " bytes" << std::endl;
#endif
				rcvbuf.push_back(m_vChoiceUpdateRcvBuf[i][j]->GetArr());
				rcvbytes.push_back(ceil_divide(m_nChoiceUpdateRcvCtr[i][j], 8));
			}
			if(m_nMaskUpdateRcvCtr[i][j] > 0) {
#ifdef DEBUG_SPLUT
			std::cout << "want to receive masks of size " << ceil_divide(m_nMaskUpdateRcvCtr[i][j], 8) << " bytes" << std::endl;
#endif
				rcvbuf.push_back(m_vMaskUpdateRcvBuf[i][j]->GetArr());
				rcvbytes.push_back(ceil_divide(m_nMaskUpdateRcvCtr[i][j], 8));
			}
		}
	}
}

inline void SetupLUT::InstantiateGate(GATE* gate) {
	gate->gs.val = (UGATE_T*) calloc((ceil_divide(gate->nvals, GATE_T_BITS)), sizeof(UGATE_T));
	gate->instantiated = true;
}

void SetupLUT::EvaluateSIMDGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	uint32_t vsize = gate->nvals;

#ifdef BENCHBOOLTIME
	timeval tstart, tend;
	gettimeofday(&tstart, NULL);
#endif

	if (gate->type == G_COMBINE) {
#ifdef DEBUGSHARING
		std::cout << " which is a COMBINE gate" << std::endl;
#endif

		uint32_t* input = gate->ingates.inputs.parents;
		uint32_t nparents = gate->ingates.ningates;
		InstantiateGate(gate);
		CBitVector tmp;

		tmp.AttachBuf((uint8_t*) gate->gs.val, (int) ceil_divide(vsize, 8));

		for(uint64_t i = 0, bit_ctr = 0; i < nparents; i++) {
			uint64_t in_size = m_vGates[input[i]].nvals;

			tmp.SetBits((uint8_t*) m_vGates[input[i]].gs.val, bit_ctr, in_size);
			bit_ctr += in_size;
		}

		tmp.DetachBuf();
#ifdef BENCHBOOLTIME
		gettimeofday(&tend, NULL);
		m_nCombTime += getMillies(tstart, tend);
#endif

		free(input);
	} else if (gate->type == G_SPLIT) {
#ifdef DEBUGSHARING
		std::cout << " which is a SPLIT gate" << std::endl;
#endif
		uint32_t pos = gate->gs.sinput.pos;
		uint32_t idparent = gate->ingates.inputs.parent;
		InstantiateGate(gate);
		//TODO: optimize
		for (uint32_t i = 0; i < vsize; i++) {
			gate->gs.val[i / GATE_T_BITS] |= ((m_vGates[idparent].gs.val[(pos + i) / GATE_T_BITS] >> ((pos + i) % GATE_T_BITS)) & 0x1) << (i % GATE_T_BITS);
		}
		UsedGate(idparent);
	} else if (gate->type == G_REPEAT) //TODO only meant for single bit values, update
			{
#ifdef DEBUGSHARING
		std::cout << " which is a REPEATER gate" << std::endl;
#endif
		uint32_t idparent = gate->ingates.inputs.parent;
		InstantiateGate(gate);

		BYTE byte_val = m_vGates[idparent].gs.val[0] ? MAX_BYTE : ZERO_BYTE;
		memset(gate->gs.val, byte_val, sizeof(UGATE_T) * ceil_divide(vsize, GATE_T_BITS));
		UsedGate(idparent);
	} else if (gate->type == G_PERM) {
#ifdef DEBUGSHARING
		std::cout << " which is a PERMUTATION gate" << std::endl;
#endif
		//std::cout << "I am evaluating a permutation gate" << std::endl;
		uint32_t* inputs = gate->ingates.inputs.parents;
		uint32_t* posids = gate->gs.perm.posids;

		InstantiateGate(gate);

		//TODO: there might be a problem here since some bits might not be set to zero
		memset(gate->gs.val, 0x00, ceil_divide(vsize, 8));

		//TODO: Optimize
		for (uint32_t i = 0; i < vsize; i++) {
			gate->gs.val[i / GATE_T_BITS] |= (((m_vGates[inputs[i]].gs.val[posids[i] / GATE_T_BITS] >> (posids[i] % GATE_T_BITS)) & 0x1) << (i % GATE_T_BITS));
			UsedGate(inputs[i]);
		}
		free(inputs);
		free(posids);
	} else if (gate->type == G_COMBINEPOS) {
#ifdef DEBUGSHARING
		std::cout << " which is a COMBINEPOS gate" << std::endl;
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
			gate->gs.val[i / GATE_T_BITS] |= (((m_vGates[idparent].gs.val[arraypos] >> bitpos) & 0x1) << (i % GATE_T_BITS));
			UsedGate(idparent);
		}
		free(combinepos);
	} else if (gate->type == G_SUBSET) {
#ifdef DEBUGSHARING
		std::cout << " which is a Subset gate" << std::endl;
#endif
		uint32_t idparent = gate->ingates.inputs.parent;
		uint32_t* positions = gate->gs.sub_pos.posids; //gate->gs.combinepos.input;
		bool del_pos = gate->gs.sub_pos.copy_posids;
		uint32_t arraypos;
		uint32_t bitpos;
		InstantiateGate(gate);
		memset(gate->gs.val, 0x00, ceil_divide(vsize, 8));
		UGATE_T* valptr = m_vGates[idparent].gs.val;
		for (uint32_t i = 0; i < vsize; i++) {
			//arraypos = positions[i] / GATE_T_BITS;
			//bitpos = positions[i] % GATE_T_BITS;
			//gate->gs.val[i / GATE_T_BITS] |= (((m_vGates[idparent].gs.val[arraypos] >> bitpos) & 0x1) << (i % GATE_T_BITS));
			arraypos = positions[i] >> 6;
			bitpos = positions[i] & 0x3F;
			gate->gs.val[i >> 6] |= (((valptr[arraypos] >> bitpos) & 0x1) << (i & 0x3F));
		}
		UsedGate(idparent);
		if(del_pos)
			free(positions);
#ifdef BENCHBOOLTIME
		gettimeofday(&tend, NULL);
		m_nSubsetTime += getMillies(tstart, tend);
#endif
	} else if (gate->type == G_STRUCT_COMBINE) {
#ifdef DEBUGSHARING
		std::cout << " which is a Subset gate" << std::endl;
#endif
		//std::cout << "I am evaluating a structurized combiner gate" << std::endl;
		uint32_t* inputs = gate->ingates.inputs.parents;
		uint32_t pos_start = gate->gs.struct_comb.pos_start;
		uint32_t pos_incr = gate->gs.struct_comb.pos_incr;
		uint32_t ninputs = gate->gs.struct_comb.num_in_gates;

		InstantiateGate(gate);

		//TODO: there might be a problem here since some bits might not be set to zero
		memset(gate->gs.val, 0x00, ceil_divide(vsize, 8));

		//TODO: Optimize
		//std::cout << "ninputs = " << ninputs << ", nvals = " << vsize  << std::endl;
		for(uint32_t pos_ctr = pos_start, ctr=0, p_tmp_idx, p_tmp_pos; ctr<vsize; pos_ctr+=pos_incr) {
			p_tmp_idx = pos_ctr / GATE_T_BITS;
			p_tmp_pos = pos_ctr % GATE_T_BITS;
			for(uint32_t in_ctr = 0; in_ctr<ninputs; in_ctr++, ctr++) {
				gate->gs.val[ctr / GATE_T_BITS] |= (((m_vGates[inputs[in_ctr]].gs.val[p_tmp_idx] >> p_tmp_pos) & 0x1) << (ctr % GATE_T_BITS));
				//gate->gs.val[ctr / GATE_T_BITS] |= (((m_vGates[inputs[in_ctr]].gs.val[pos_ctr / GATE_T_BITS] >> (pos_ctr % GATE_T_BITS)) & 0x1) << (ctr % GATE_T_BITS));
			}
		}

		//for (uint32_t i = 0, in_ctr=0, pos_ctr=pos_start; i < vsize; i++, in_ctr=(in_ctr+1)%ninputs, pos_ctr+=pos_incr ) {
		//	gate->gs.val[i / GATE_T_BITS] |= (((m_vGates[inputs[in_ctr]].gs.val[pos_ctr / GATE_T_BITS] >> (pos_ctr % GATE_T_BITS)) & 0x1) << (i % GATE_T_BITS));
		//}

		for(uint32_t i = 0; i < ninputs; i++) {
			UsedGate(inputs[i]);
		}

		free(inputs);
#ifdef BENCHBOOLTIME
		gettimeofday(&tend, NULL);
		m_nCombStructTime += getMillies(tstart, tend);
#endif
	}
#ifdef BENCHBOOLTIME
	gettimeofday(&tend, NULL);
	m_nSIMDTime += getMillies(tstart, tend);
#endif
}

Circuit* SetupLUT::GetCircuitBuildRoutine() {
	return m_cBoolCircuit;
}

uint32_t SetupLUT::AssignInput(CBitVector& inputvals) {
	std::deque<uint32_t> myingates = m_cBoolCircuit->GetInputGatesForParty(m_eRole);
	inputvals.Create((uint64_t) m_cBoolCircuit->GetNumInputBitsForParty(m_eRole), m_cCrypto);

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

uint32_t SetupLUT::GetOutput(CBitVector& out) {
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

uint32_t SetupLUT::GetMaxCommunicationRounds() {
	return m_cBoolCircuit->GetMaxDepth()+1;
}

void SetupLUT::PrintPerformanceStatistics() {
	std::cout << "SP-LUT Sharing: OT-gates: ";
	uint64_t total_not_gates = 0;
	for (uint32_t i = 0; i < m_vNOTs[0].size(); i++) {
		//TODO: udpdate
		uint32_t notgates = m_vNOTs[0][i][0].numgates + m_vNOTs[1][i][0].numgates;
		if(notgates>0) {
			std::cout << "1oo" << m_vNOTs[0][i][0].tt_len << ": " << notgates << "; ";
		}
		total_not_gates += notgates;
	}
	std::cout << "Total OT gates = " << total_not_gates << "; ";

	std::cout << "Depth: " << GetMaxCommunicationRounds() << std::endl;

/*	std::cout << "XOR vals: "<< m_cBoolCircuit->GetNumXORVals() << " gates: "<< m_cBoolCircuit->GetNumXORGates() << std::endl;
	std::cout << "Comb gates: " << m_cBoolCircuit->GetNumCombGates() << ", CombStruct gates: " <<  m_cBoolCircuit->GetNumStructCombGates() <<
			", Perm gates: "<< m_cBoolCircuit->GetNumPermGates() << ", Subset gates: " << m_cBoolCircuit->GetNumSubsetGates() <<
			", Split gates: "<< m_cBoolCircuit->GetNumSplitGates() << std::endl;*/
#ifdef BENCHBOOLTIME
	std::cout << "XOR time " << m_nXORTime << ", SIMD time " << m_nSIMDTime << ", Comb time: " << m_nCombTime << ", Comb structurized time: " <<
			m_nCombStructTime << ", Subset time: " << m_nSubsetTime << std::endl;
#endif
}

void SetupLUT::Reset() {
	m_nTotalTTs = 0;
	m_nXORGates = 0;

	m_nNumANDSizes = 0;

	m_vInputShareGates.clear();
	m_vOutputShareGates.clear();

	m_nInputShareSndSize = 0;
	m_nOutputShareSndSize = 0;

	m_nInputShareRcvSize = 0;
	m_nOutputShareRcvSize = 0;

	//Delete the pre-computed OT values
	for (uint32_t i = 0; i < m_vPreCompOTX.size(); i++) {
		for(uint32_t k = 0; k < m_vPreCompOTX[i].size(); k++) {
			for(uint32_t j = 0; j < (uint32_t) (1<<i); j++) {
				delete m_vPreCompOTX[i][k][j];
			}
			free(m_vPreCompOTX[i][k]);
			//m_vPreCompOTX[i][k].resize(0);
			//free(m_vPreCompOTX[i]);
			delete m_vPreCompOTMasks[i][k];

			delete m_vPreCompOTC[i][k];
			delete m_vPreCompOTR[i][k];

			//TODO: setting to 0 is probably not required. test this and remove if so
			m_vPreCompMaskIdx[i][k] = 0;
			m_vPreCompChoiceIdx[i][k] = 0;

			m_nMaskUpdateSndCtr[i][k] = 0;
			delete m_vMaskUpdateSndBuf[i][k];
			m_nMaskUpdateRcvCtr[i][k] = 0;
			delete m_vMaskUpdateRcvBuf[i][k];

			m_nChoiceUpdateSndCtr[i][k] = 0;
			delete m_vChoiceUpdateSndBuf[i][k];
			m_nChoiceUpdateRcvCtr[i][k] = 0;
			delete m_vChoiceUpdateRcvBuf[i][k];

			m_nTableRndIdx[i][k] = 0;
			delete m_vTableRnd[i][k];
		}
		m_vPreCompOTX[i].resize(0);
		m_vPreCompOTMasks[i].resize(0);
		m_vPreCompOTC[i].resize(0);
		m_vPreCompOTR[i].resize(0);

		m_vPreCompMaskIdx[i].resize(0);
		m_vPreCompChoiceIdx[i].resize(0);

		m_nMaskUpdateSndCtr[i].resize(0);
		m_vMaskUpdateSndBuf[i].resize(0);
		m_nMaskUpdateRcvCtr[i].resize(0);
		m_vMaskUpdateRcvBuf[i].resize(0);

		m_nChoiceUpdateSndCtr[i].resize(0);
		m_vChoiceUpdateSndBuf[i].resize(0);
		m_nChoiceUpdateRcvCtr[i].resize(0);
		m_vChoiceUpdateRcvBuf[i].resize(0);

		m_nTableRndIdx[i].resize(0);
		m_vTableRnd[i].resize(0);

	}
	///m_vPreCompOTC.clear();
	//m_vPreCompOTR.clear();
	//m_vNOTs.clear();

	m_vInputShareSndBuf.delCBitVector();
	m_vOutputShareSndBuf.delCBitVector();

	m_vInputShareRcvBuf.delCBitVector();
	m_vOutputShareRcvBuf.delCBitVector();

	m_cBoolCircuit->Reset();

	for(uint32_t i = 0; i < m_vTTGates.size(); i++) {
		m_vTTGates[i].clear();
	}

	for(uint32_t i = 0; i < m_vSndBufStash.size(); i++) {
		free(m_vSndBufStash[i]);
	}
	m_vSndBufStash.clear();
	m_vSndBytesStash.clear();

	m_bPlaySender = !((bool) m_eRole);

	//reset the required OTs
	for(uint32_t i = 0; i < m_vNOTs[0].size(); i++) {
		m_vNOTs[0][i].resize(1);
		m_vNOTs[0][i][0].tt_len = (1<<i);
		m_vNOTs[0][i][0].numgates = 0;
		m_vNOTs[0][i][0].out_bits = 1;

		m_vNOTs[1][i].resize(1);
		m_vNOTs[1][i][0].tt_len = (1<<i);
		m_vNOTs[1][i][0].numgates = 0;
		m_vNOTs[1][i][0].out_bits = 1;
	}
}
