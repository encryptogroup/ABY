/**
 \file 		boolsharing.cpp
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
 \brief		Bool sharing class implementation.
 */
#include "boolsharing.h"
#include "../aby/abysetup.h"
#include <cstdlib>

#if __has_include(<filesystem>)
#include <filesystem>
namespace filesystem = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#include <experimental/filesystem>
namespace filesystem = std::experimental::filesystem;
#else
#error "C++17 filesystem library not found"
#endif


void BoolSharing::Init() {

	m_nTotalNumMTs = 0;
	m_nXORGates = 0;
	m_nOPLUT_Tables = 0;

	m_nNumANDSizes = 0;

	m_nInputShareSndSize = 0;
	m_nOutputShareSndSize = 0;
	m_nInputShareRcvSize = 0;
	m_nOutputShareRcvSize = 0;

	m_cBoolCircuit = new BooleanCircuit(m_pCircuit, m_eRole, m_eContext, m_cCircuitFileDir);

#ifdef BENCHBOOLTIME
	m_nCombTime = 0;
	m_nSubsetTime = 0;
	m_nCombStructTime = 0;
	m_nSIMDTime = 0;
	m_nXORTime = 0;
#endif
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

	for(auto it=m_vOPLUTGates.begin(); it!=m_vOPLUTGates.end(); it++) {
		it->second.clear();
	}

	m_vInputShareGates.clear();
	m_vOutputShareGates.clear();


	for(auto it=m_vOP_LUT_SelOpeningBitCtr.begin(); it!=m_vOP_LUT_SelOpeningBitCtr.end(); it++) {
		it->second = 0;
		//if(it->second > 0) {
		//	sendbuf.push_back(m_vOP_LUT_RecSelOpeningBuf[it->first]->GetArr());
		//	sndbytes.push_back(ceil_divide(it->second, 8));
		//}
	}
}

void BoolSharing::PrepareSetupPhase(ABYSetup* setup) {
	m_nNumANDSizes = m_cBoolCircuit->GetANDs(m_vANDs);


	/**Checking the role of the executor. Based on the role a specific file is selected.*/
	//TODO use strings
	char filename[21];
	if(m_eRole == SERVER) {
		strcpy(filename, "pre_comp_server.dump");
	}
	else {
		strcpy(filename, "pre_comp_client.dump");
	}


	m_nTotalNumMTs = 0;
	m_nNumMTs.resize(m_nNumANDSizes);
	for (uint32_t i = 0; i < m_nNumANDSizes; i++) {
		//Is needed to pad the MTs to a byte, deleting this will make the online phase really messy and (probably) inefficient
		m_nNumMTs[i] = m_vANDs[i].numgates > 0? m_vANDs[i].numgates + (8 * m_cBoolCircuit->GetMaxDepth()) : m_vANDs[i].numgates;
		m_nTotalNumMTs += m_vANDs[i].numgates;
	}

	//8*circuit_depth are needed since the mtidx is padded to the next byte after each layer
	if (m_nTotalNumMTs > 0)
		m_nTotalNumMTs += (8 * m_cBoolCircuit->GetMaxDepth());

	InitializeMTs();

	/**
		Checking if the precomputation mode is READ. If so, checking if the circuit size configured is
		within the provided specification of the precomputation values stored in the file.
		If it not within the spec, reverting to default mode.
	*/
	if((GetPreCompPhaseValue()==ePreCompRead)&&(!isCircuitSizeLessThanOrEqualWithValueFromFile(filename, m_nNumANDSizes))) {
			SetPreCompPhaseValue(ePreCompDefault);
	}



	/*
	 * If no MTs need to be pre-computed omit this method
	 */
	if(m_nTotalNumMTs > 0) {
		PrepareSetupPhaseMTs(setup);

	}
	/*
	 * If no OP-LUT tables need to be pre-computed omit this method
	 */
	//Get the data that corresponds to the OP-LUT tables
	//tmplens: first dimension: circuit depth, second dimension: num-inputs, third dimension: out_bitlen. We can ignore the circuit depth here!
	std::vector<std::vector<std::vector<tt_lens_ctx> > > tmplens = m_cBoolCircuit->GetTTLens();
	if (!(tmplens.size() == 1 && tmplens[0].size() == 1 && tmplens[0][0].size() == 1 && tmplens[0][0][0].numgates == 0)) {
		PrepareSetupPhaseOPLUT(setup);
	}

}


void BoolSharing::PrepareSetupPhaseMTs(ABYSetup* setup) {
	/**
		   If the precomputation is READ or in Reading phase when in RAM mode, the MTs doesn't need to be
		   computed again and therefore following check is done.
	 */
	if((GetPreCompPhaseValue() != ePreCompRead)&&(GetPreCompPhaseValue() != ePreCompRAMRead)) {

#ifdef USE_KK_OT_FOR_MT
		for (uint32_t j = 0; j < 2; j++) {
			KK_OTTask* task = (KK_OTTask*) malloc(sizeof(KK_OTTask));
			task->bitlen = m_vANDs[0].bitlen;
			task->snd_flavor = Snd_OT;
			task->rec_flavor = Rec_OT;
			task->nsndvals = 4;
			task->numOTs = ceil_divide(m_nNumMTs[0], 2);
			task->mskfct = new XORMasking(m_vANDs[0].bitlen);
			task->delete_mskfct = TRUE;
			if ((m_eRole ^ j) == SERVER) {
				task->pval.sndval.X = m_vKKS.data();
			} else {
				task->pval.rcvval.C = m_vKKChoices[m_eRole^1];
				task->pval.rcvval.R = &(m_vKKC[m_eRole^1]);
			}
#ifndef BATCH
			std::cout << "Adding new KK OT task for " << task->numOTs << " OTs on " << task->bitlen << " bit-strings" << std::endl;
#endif
			setup->AddOTTask(task, j);
		}
		for (uint32_t i = 1; i < m_nNumANDSizes; i++) {
#else
		for (uint32_t i = 0; i < m_nNumANDSizes; i++) {
#endif
			for (uint32_t j = 0; j < 2; j++) {
				IKNP_OTTask* task = (IKNP_OTTask*) malloc(sizeof(IKNP_OTTask));
				task->bitlen = m_vANDs[i].bitlen;
				task->snd_flavor = Snd_R_OT;
				task->rec_flavor = Rec_OT;
				task->numOTs = m_nNumMTs[i];
				task->mskfct = new XORMasking(m_vANDs[i].bitlen);
				task->delete_mskfct = TRUE;
				if ((m_eRole ^ j) == SERVER) {
					task->pval.sndval.X0 = &(m_vC[i]);
					task->pval.sndval.X1 = &(m_vB[i]);
				} else {
					task->pval.rcvval.C = &(m_vA[i]);
					task->pval.rcvval.R = &(m_vS[i]);
				}
#ifndef BATCH
				std::cout << "Adding new OT task for " << task->numOTs << " OTs on " << task->bitlen << " bit-strings" << std::endl;
#endif
				setup->AddOTTask(task, j);
			}
		}
	}
}

//Initialize data for the OP-LUT protocol, count how many tables need to be pre-computed, and set the number of OTs that need to be computed
void BoolSharing::PrepareSetupPhaseOPLUT(ABYSetup* setup) {
	std::vector<std::vector<std::vector<tt_lens_ctx> > > tmplens = m_cBoolCircuit->GetTTLens();
	uint32_t rnd_rot_bits, rnd_table_bits;
	uint64_t address, n_inbits, n_outbits;
	std::map<uint64_t, uint64_t> max_num_gates; //keeps track of the maximum number of OP-LUT gates for the layers of each input/output combination

	std::vector<std::vector<tt_lens_ctx> > depth_red_tmplens(tmplens[0].size());
	for(uint32_t i = 0; i < tmplens[0].size(); i++) {
		depth_red_tmplens[i].resize(tmplens[0][i].size());

		for(uint32_t j = 0; j < tmplens[0][i].size(); j++) {
			depth_red_tmplens[i][j].tt_len = tmplens[0][i][j].tt_len;
			depth_red_tmplens[i][j].out_bits = tmplens[0][i][j].out_bits;
			depth_red_tmplens[i][j].numgates = 0;
			address = (uint64_t) ceil_log2(depth_red_tmplens[i][j].tt_len);
			address = (address << 32) | ((uint64_t) depth_red_tmplens[i][j].out_bits);
			max_num_gates[address] = 0;

			//sum all gates up and combine all tables onto a single buffer
			for(uint32_t d = 0; d < tmplens.size(); d++) {
				if(tmplens[d][i][j].numgates > 0) {
					depth_red_tmplens[i][j].numgates += tmplens[d][i][j].numgates;
					depth_red_tmplens[i][j].ttable_values.reserve(depth_red_tmplens[i][j].numgates);

					depth_red_tmplens[i][j].ttable_values.insert(depth_red_tmplens[i][j].ttable_values.end(),
							tmplens[d][i][j].ttable_values.begin(), tmplens[d][i][j].ttable_values.end());

					//conditional update on the maximal number of gates
					if(tmplens[d][i][j].numgates > max_num_gates[address]) {
						max_num_gates[address] = tmplens[d][i][j].numgates;
					}
				}
			}
		}
	}

	for(uint32_t i = 0; i < depth_red_tmplens.size(); i++) {
		for(uint32_t j = 0; j < depth_red_tmplens[i].size(); j++) {
			if(depth_red_tmplens[i][j].numgates > 0) {
				n_inbits = ceil_log2(depth_red_tmplens[i][j].tt_len);
				n_outbits = depth_red_tmplens[i][j].out_bits;

				op_lut_ctx* lut_data = (op_lut_ctx*) malloc(sizeof(op_lut_ctx));
				lut_data->sel_opening_ctr = 0;
				lut_data->mask_ctr = 0;
				lut_data->n_inbits = n_inbits;
				lut_data->n_outbits = n_outbits;
				lut_data->n_gates = depth_red_tmplens[i][j].numgates;
				m_nOPLUT_Tables += lut_data->n_gates;

				//Initialize and generate the random rotation values
				rnd_rot_bits = n_inbits * depth_red_tmplens[i][j].numgates;
				lut_data->rot_val = new CBitVector(rnd_rot_bits, m_cCrypto);
				if(m_eRole == CLIENT) {
					//TODO: There is a really strange problem that makes this routine fail for larger sizes. This hack is required to get rid of the problem!
					CBitVector* tmp = new CBitVector(rnd_rot_bits, m_cCrypto);
					for(uint32_t p = 0; p < lut_data->n_gates; p++) {
						lut_data->rot_val->Set<uint8_t>(tmp->Get<uint8_t>(p*n_inbits, n_inbits)&0x0F, p * n_inbits, n_inbits);
					}
					tmp->delCBitVector();
				}

				//Initialize the truth table. The server will generate its randomness in this vector while the client will assign the output of the OT to it
				rnd_table_bits = depth_red_tmplens[i][j].tt_len * n_outbits * lut_data->n_gates;
				lut_data->table_mask = new CBitVector(rnd_table_bits);
				if(m_eRole == SERVER) {
					lut_data->table_mask->FillRand(rnd_table_bits, m_cCrypto);
				}

				//copy the pointers to the truth table values

				lut_data->table_data = depth_red_tmplens[i][j].ttable_values.data();

				//The server initializes the possible values for the OT and pre-compute the rotated truth-tables
				//TODO: Optimize with rotation instead of Set Bits! Also change loop order to make it more efficient!
				if(m_eRole == SERVER) {
					// uint32_t tab_ele_bits = sizeof(uint64_t) * 8;
					uint32_t tt_len = 1<<lut_data->n_inbits;
					lut_data->rot_OT_vals = (CBitVector**) malloc(sizeof(CBitVector*) * tt_len);

					for(uint32_t s = 0; s < tt_len; s++) {
						lut_data->rot_OT_vals[s] = new CBitVector(rnd_table_bits);
						for(uint32_t m = 0; m < lut_data->n_gates; m++) {
							uint64_t rot_val = lut_data->rot_val->Get<uint64_t>(m * n_inbits, n_inbits)^s; //compute r \oplus s for all possible s
							uint64_t* tab_ptr = lut_data->table_data[m];

							//tmp_tab.AttachBuf(ut_data->table_data[m], ceil_divide(tt_len * n_outbits, 8));
							//lut_data->rot_OT_vals.SetBitsRot((uint8_t*) lut_data->table_data[m], l, m * (1<<lut_data->n_inbits), 1<<lut_data->n_inbits);
							for(uint32_t n = 0; n < tt_len; n++) {
								lut_data->rot_OT_vals[s]->SetBitsPosOffset((uint8_t*) tab_ptr, (rot_val^n) * lut_data->n_outbits, m*tt_len*lut_data->n_outbits+n * lut_data->n_outbits, lut_data->n_outbits);
										//.Getm * tt_len+n, (tt_ptr[(n^rot_val)/tab_ele_bits]>>((n^rot_val)%tab_ele_bits))&0x01);
							}
						}
						lut_data->rot_OT_vals[s]->XORBits(lut_data->table_mask->GetArr(), 0, rnd_table_bits);
					}
				}

				//insert the lut into the map
				address = (n_inbits << 32) | (n_outbits);
				m_vOP_LUT_data.insert(std::pair<uint64_t, op_lut_ctx*>(address, lut_data));
				CBitVector* snd_sel_opening_buf = new CBitVector(lut_data->n_inbits * max_num_gates[address]);
				CBitVector* rec_sel_opening_buf = new CBitVector(lut_data->n_inbits * max_num_gates[address]);
				m_vOP_LUT_SndSelOpeningBuf.insert(std::pair<uint64_t, CBitVector*>(address, snd_sel_opening_buf));
				m_vOP_LUT_RecSelOpeningBuf.insert(std::pair<uint64_t, CBitVector*>(address, rec_sel_opening_buf));
				//	std::cout << "Created new OP-LUT data structure with " << n_inbits << " input bits, " << n_outbits << " output bits, and "<<
				//			tmplens[i][i][j].numgates << " gates" << std::endl;
			}
		}
	}

	max_num_gates.clear();


	//iterate over all elements in the map and create new 1ooN OT-tasks for each of them
	for(auto it=m_vOP_LUT_data.begin(); it!=m_vOP_LUT_data.end(); it++) {

		//for (uint32_t j = 0; j < 2; j++) {
		KK_OTTask* task = (KK_OTTask*) malloc(sizeof(KK_OTTask));
		task->bitlen = (1<<it->second->n_inbits) * it->second->n_outbits;
		task->snd_flavor = Snd_OT;
		task->rec_flavor = Rec_OT;
		task->nsndvals = 1<<it->second->n_inbits;
		task->numOTs = it->second->n_gates;

		fMaskFct = new XORMasking(task->bitlen);
		task->mskfct = fMaskFct;
		task->delete_mskfct = TRUE;
		if (m_eRole == SERVER) {
			//std::cout << "I assigned sender" << std::endl;
			task->pval.sndval.X = it->second->rot_OT_vals;
		} else {
			task->pval.rcvval.C = it->second->rot_val;
			task->pval.rcvval.R = it->second->table_mask;
		}
//#ifndef BATCH
		std::cout << "Adding new 1oo" << task->nsndvals << " OT task for " << task->numOTs << " OTs on " << task->bitlen << " bit-strings" << std::endl;
//#endif
		setup->AddOTTask(task, 0);
		//}
	}

}


void BoolSharing::PerformSetupPhase([[maybe_unused]] ABYSetup* setup) {
	//Do nothing
}
void BoolSharing::FinishSetupPhase([[maybe_unused]]  ABYSetup* setup) {
	if (m_nTotalNumMTs == 0 && m_nOPLUT_Tables == 0)
		return;

	//Compute Multiplication Triples
	//ComputeMTs();

	/**Entering precomputation decision function.*/
	PreComputationPhase();

	//Delete the X values for OP-LUT of the sender when pre-computing the OTs
	for(auto it=m_vOP_LUT_data.begin(); it!=m_vOP_LUT_data.end(); it++) {
		if(it->second->n_gates > 0 && m_eRole == SERVER) {
			for(uint32_t i = 0; i < (uint32_t) 1<<it->second->n_inbits; i++) {
				it->second->rot_OT_vals[i]->delCBitVector();
			}
			free(it->second->rot_OT_vals);
		}
#ifdef DEBUGBOOL
		if(it->second->n_gates > 0 && m_eRole == CLIENT) {
			std::cout << "Resutling shared table:" << std::endl;
			it->second->table_mask->PrintHex();
		}
#endif
	}


#ifdef DEBUGBOOL
	std::cout << "A: ";
	m_vA[0].PrintBinary();
	std::cout << "B: ";
	m_vB[0].PrintBinary();
	std::cout << "C: ";
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

	uint64_t mtbitlen;
	for (uint32_t i = 0; i < m_nNumANDSizes; i++) {
		if(i == 0) mtbitlen = 1;
		else mtbitlen = PadToMultiple(m_vANDs[i].bitlen, 8);
		//A contains the  choice bits for the OTs
		m_vA[i].Create(m_nNumMTs[i], m_cCrypto);
		//B contains the correlation between the OTs
		m_vB[i].Create(m_nNumMTs[i] * mtbitlen, m_cCrypto);
		//C contains the zero mask and is later computed correctly
		m_vC[i].Create(m_nNumMTs[i] * mtbitlen);
		//S is a temporary buffer and contains the result of the OTs where A is used as choice bits
		m_vS[i].Create(m_nNumMTs[i] * mtbitlen);

		//D snd and rcv contain the masked A values
		m_vD_snd[i].Create(m_nNumMTs[i]);
		m_vD_rcv[i].Create(m_nNumMTs[i]);
		//E contains the masked B values
		m_vE_snd[i].Create(m_nNumMTs[i] * mtbitlen);
		m_vE_rcv[i].Create(m_nNumMTs[i] * mtbitlen);
		//ResA and ResB are temporary results
		m_vResA[i].Create(m_nNumMTs[i] * mtbitlen);
		m_vResB[i].Create(m_nNumMTs[i] * mtbitlen);
	}

#ifdef USE_KK_OT_FOR_MT
	m_vKKA.resize(2);
	m_vKKB.resize(2);
	m_vKKC.resize(2);
	m_vKKChoices.resize(2);
	m_vKKS.resize(4);

	for(uint32_t i = 0; i < 2; i++) {
		m_vKKA[i].Create(ceil_divide(m_nNumMTs[0], 2), m_cCrypto);
		m_vKKB[i].Create(ceil_divide(m_nNumMTs[0], 2), m_cCrypto);
		m_vKKC[i].Create(ceil_divide(m_nNumMTs[0], 2), m_cCrypto);
	}
	CBitVector* Ainv = new CBitVector();
	CBitVector* Binv = new CBitVector();
	Ainv->Copy(m_vKKA[m_eRole]);
	Ainv->Invert();
	Binv->Copy(m_vKKB[m_eRole]);
	Binv->Invert();
	CBitVector* tmpA[2];
	CBitVector* tmpB[2];
	tmpA[0] = &m_vKKA[m_eRole];
	tmpA[1] = Ainv;
	tmpB[0] = &m_vKKB[m_eRole];
	tmpB[1] = Binv;

	for(uint32_t i = 0; i < 4; i++) {
		m_vKKS[i] = new CBitVector();
		m_vKKS[i]->Copy(*(tmpA[i>>1]));
		m_vKKS[i]->AND(tmpB[i&0x01]);
		m_vKKS[i]->XOR(&(m_vKKC[m_eRole]));
	}

	//Merge the A and B values into one vector on receiver side
	m_vKKChoices[m_eRole^1] = new CBitVector();
	m_vKKChoices[m_eRole^1]->Create(m_nNumMTs[0]);
	for(uint32_t i = 0; i < ceil_divide(m_nNumMTs[0], 2); i++) {
		m_vKKChoices[m_eRole^1]->SetBitNoMask(2*i, m_vKKB[m_eRole^1].GetBitNoMask(i));
		m_vKKChoices[m_eRole^1]->SetBitNoMask(2*i+1, m_vKKA[m_eRole^1].GetBitNoMask(i));
	}
#endif
}

void BoolSharing::PrepareOnlinePhase() {

	//get #in/output bits for other party
	uint32_t insharesndbits = m_cBoolCircuit->GetNumInputBitsForParty(m_eRole);
	uint32_t outsharesndbits = m_cBoolCircuit->GetNumOutputBitsForParty(m_eRole==SERVER ? CLIENT : SERVER);
	uint32_t insharercvbits = m_cBoolCircuit->GetNumInputBitsForParty(m_eRole==SERVER ? CLIENT : SERVER);
	uint32_t outsharercvbits = m_cBoolCircuit->GetNumOutputBitsForParty(m_eRole);

	m_vInputShareSndBuf.Create(insharesndbits, m_cCrypto);

	m_vOutputShareSndBuf.Create(outsharesndbits);
	m_vInputShareRcvBuf.Create(insharercvbits);
	m_vOutputShareRcvBuf.Create(outsharercvbits);

	m_vANDGates.resize(m_nNumANDSizes);

	InitNewLayer();

}

void BoolSharing::ComputeMTs() {
	//std::cout << "Computing MTs " << std::endl;
	CBitVector temp;

#ifdef USE_KK_OT_FOR_MT
	uint64_t len = (uint64_t) ceil_divide(m_nNumMTs[0], 2);
	for(uint32_t i = 0; i < 2; i++) {
		m_vA[0].SetBits(m_vKKA[i].GetArr(), i*len, len);
		m_vB[0].SetBits(m_vKKB[i].GetArr(), i*len, len);
		m_vC[0].SetBits(m_vKKC[i].GetArr(), i*len, len);
	}


	//m_vB[0].SetBits(m_vKKB[0].GetArr(), (uint64_t) 0L, (uint64_t) ceil_divide(m_nNumMTs[0], 2));
	//m_vB[0].SetBits(m_vKKB[1].GetArr(), (uint64_t) ceil_divide(m_nNumMTs[0], 2), (uint64_t) ceil_divide(m_nNumMTs[0], 2));

	//m_vC[0].SetBits(m_vKKC[0].GetArr(), (uint64_t) 0L, (uint64_t) ceil_divide(m_nNumMTs[0], 2));
	//m_vC[0].SetBits(m_vKKC[1].GetArr(), (uint64_t) ceil_divide(m_nNumMTs[0], 2), (uint64_t) ceil_divide(m_nNumMTs[0], 2));

	//Pre-store the values in A and B in D_snd and E_snd
	m_vD_snd[0].Copy(m_vA[0].GetArr(), 0, bits_in_bytes(m_nNumMTs[0]));
	m_vE_snd[0].Copy(m_vB[0].GetArr(), 0, bits_in_bytes(m_nNumMTs[0]));

	m_vKKChoices[m_eRole^1]->delCBitVector();
	for(uint32_t i = 0; i < 4; i++) {
		m_vKKS[i]->delCBitVector();
	}

	for (uint32_t i = 1; i < m_nNumANDSizes; i++) {
#else
	for (uint32_t i = 0; i < m_nNumANDSizes; i++) {
#endif
		//std::cout << "I = " << i << ", len = " << m_vANDs[i].bitlen << ", Num= " << m_nNumMTs[i] <<std::endl;
		uint32_t andbytelen = ceil_divide(m_nNumMTs[i], 8);
		uint32_t stringbytelen = ceil_divide(m_nNumMTs[i] * m_vANDs[i].bitlen, 8);

		temp.Create(stringbytelen * 8);
		temp.Reset();

		//Get correct B
		m_vB[i].XORBytes(m_vC[i].GetArr(), 0, stringbytelen);

		//Compute the correct C
		if (m_vANDs[i].bitlen == 1) { //for bits
			temp.SetAND(m_vA[i].GetArr(), m_vB[i].GetArr(), 0, andbytelen);
		} else if ((m_vANDs[i].bitlen & 0x07) == 0) { //for bytes
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
		std::cout << "MT types for bitlen: " << m_vANDs[i].bitlen << std::endl;
		std::cout << "A: ";
		m_vA[i].PrintBinary();
		std::cout << "B: ";
		m_vB[i].PrintHex();
		std::cout << "C: ";
		m_vC[i].PrintHex();
#endif
		temp.delCBitVector();
	}

}

void BoolSharing::EvaluateLocalOperations(uint32_t depth) {
	std::deque<uint32_t> localops = m_cBoolCircuit->GetLocalQueueOnLvl(depth);
	GATE* gate;
#ifdef BENCHBOOLTIME
	timespec tstart, tend;
#endif
	for (uint32_t i = 0; i < localops.size(); i++) {
		gate = &(m_vGates[localops[i]]);

#ifdef DEBUGBOOL
		std::cout << "Evaluating local gate with id = " << localops[i] << " and type " << get_gate_type_name(gate->type) << std::endl;
#endif

		switch (gate->type) {
		case G_LIN:
#ifdef BENCHBOOLTIME
			clock_gettime(CLOCK_MONOTONIC, &tstart);
#endif
			EvaluateXORGate(localops[i]);
#ifdef BENCHBOOLTIME
			clock_gettime(CLOCK_MONOTONIC, &tend);
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
		case G_SHARED_OUT:
			InstantiateGate(gate);
			memcpy(gate->gs.val, ((GATE*) &(m_vGates[gate->ingates.inputs.parent]))->gs.val, bits_in_bytes(gate->nvals));
			UsedGate(gate->ingates.inputs.parent);
			break;
		case G_SHARED_IN:
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
		default:
			if (IsSIMDGate(gate->type)) {
				EvaluateSIMDGate(localops[i]);
			} else {
				std::cerr << "Boolsharing: Non-interactive Operation not recognized: " << (uint32_t) gate->type
						<< "(" << get_gate_type_name(gate->type) << "), stopping execution" << std::endl;
				std::exit(EXIT_FAILURE);
			}
			break;
		}
	}
}

void BoolSharing::EvaluateInteractiveOperations(uint32_t depth) {
	std::deque<uint32_t> interactiveops = m_cBoolCircuit->GetInteractiveQueueOnLvl(depth);

	for (uint32_t i = 0; i < interactiveops.size(); i++) {
		GATE* gate = &(m_vGates[interactiveops[i]]);

#ifdef DEBUGBOOL
		std::cout << "Evaluating interactive gate with id = " << interactiveops[i] << " and type " << get_gate_type_name(gate->type) << std::endl;
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
		case G_TT:
			SelectiveOpenOPLUT(interactiveops[i]);
			break;
		case G_CALLBACK:
			EvaluateCallbackGate(interactiveops[i]);
			break;
		default:
			std::cerr << "Boolsharing: Interactive Operation not recognized: " << (uint32_t) gate->type
				<< " (" << get_gate_type_name(gate->type) << "), stopping execution" << std::endl;
			std::exit(EXIT_FAILURE);
		}
	}
}

inline void BoolSharing::EvaluateXORGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	uint32_t nvals = gate->nvals;
	uint32_t idleft = gate->ingates.inputs.twin.left;
	uint32_t idright = gate->ingates.inputs.twin.right;
	InstantiateGate(gate);

	for (uint32_t i = 0; i < ceil_divide(nvals, GATE_T_BITS); i++) {
		gate->gs.val[i] = m_vGates[idleft].gs.val[i] ^ m_vGates[idright].gs.val[i];
	}

	UsedGate(idleft);
	UsedGate(idright);
}

inline void BoolSharing::EvaluateConstantGate(uint32_t gateid) {
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

#ifdef DEBUGBOOL
		std::cout << "Constant gate value: "<< value << std::endl;
#endif
}


inline void BoolSharing::ShareValues(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	UGATE_T* input = gate->gs.ishare.inval;
	InstantiateGate(gate);

	for (uint32_t i = 0, bitstocopy = gate->nvals, len; i < ceil_divide(gate->nvals, GATE_T_BITS); i++, bitstocopy -= GATE_T_BITS) {
		len = std::min(bitstocopy, (uint32_t) GATE_T_BITS);
		gate->gs.val[i] = m_vInputShareSndBuf.Get<UGATE_T>(m_nInputShareSndSize, len) ^ input[i];
#ifdef DEBUGBOOL
		std::cout << (unsigned uint32_t) gate->gs.val[i] << " = " << (unsigned uint32_t) m_vInputShareSndBuf.Get<UGATE_T>(m_nInputShareSndSize, len) << " ^ " << (unsigned uint32_t) input[i] << std::endl;
#endif
		m_nInputShareSndSize += len;
	}

	free(input);
}

inline void BoolSharing::EvaluateINVGate(uint32_t gateid) {
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
#ifdef DEBUGBOOL
	std::cout << "Evaluated INV gate " << gateid << " with result: " << (std::hex) << gate->gs.val[0] <<
	" and input: " << m_vGates[parentid].gs.val[0]<< (std::dec) << std::endl;
#endif
	UsedGate(parentid);
}

inline void BoolSharing::EvaluateCONVGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	uint32_t parentid = gate->ingates.inputs.parents[0];
	if (m_vGates[parentid].context == S_ARITH)
		std::cerr << "can't convert from arithmetic representation directly into Boolean" << std::endl;
	assert(m_vGates[parentid].context == S_YAO);
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
#ifdef DEBUGBOOL
	std::cout << "Set conversion gate value to " << gate->gs.val[0] << std::endl;
#endif

	UsedGate(parentid);
	free(gate->ingates.inputs.parents);
}

inline void BoolSharing::ReconstructValue(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	uint32_t parentid = gate->ingates.inputs.parent;
	assert(m_vGates[parentid].instantiated);
	for (uint32_t i = 0, bitstocopy = gate->nvals, len; i < ceil_divide(gate->nvals, GATE_T_BITS); i++, bitstocopy -= GATE_T_BITS) {
		len = std::min(bitstocopy, (uint32_t) GATE_T_BITS);
#ifdef DEBUGBOOL
		std::cout << "m_vOutputShareSndBuf.size = " << m_vOutputShareSndBuf.GetSize() << ", ctr = " <<m_nOutputShareSndSize << ", len = " << len << ", gate->parent = " << parentid
		<< " and val = " << (std::hex) << m_vGates[parentid].gs.val[i] << (std::dec) << std::endl;
#endif
		m_vOutputShareSndBuf.Set<UGATE_T>(m_vGates[parentid].gs.val[i], m_nOutputShareSndSize, len);	//gate->gs.val[i], len);
		m_nOutputShareSndSize += len;
	}
	if (gate->gs.oshare.dst != ALL)
		UsedGate(parentid);
}

inline void BoolSharing::SelectiveOpen(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	uint32_t idleft = gate->ingates.inputs.twin.left;
	uint32_t idright = gate->ingates.inputs.twin.right;

	for (uint32_t i = 0, bitstocopy = gate->nvals, len; i < ceil_divide(gate->nvals, GATE_T_BITS); i++, bitstocopy -= GATE_T_BITS) {
		len = std::min(bitstocopy, (uint32_t) GATE_T_BITS);
		m_vD_snd[0].XOR(m_vGates[idleft].gs.val[i], m_vMTIdx[0], len);
		m_vE_snd[0].XOR(m_vGates[idright].gs.val[i], m_vMTIdx[0], len);
		m_vMTIdx[0] += len;
#ifdef DEBUGBOOL
		std::cout << "opening " << idleft << " = " << m_vGates[idleft].gs.val[i] << " , and " << idright << " = " << m_vGates[idright].gs.val[i] << std::endl;
#endif
	}
	m_vANDGates[0].push_back(gateid);

	UsedGate(idleft);
	UsedGate(idright);
}

inline void BoolSharing::SelectiveOpenVec(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);

	uint32_t idchoice = gate->ingates.inputs.twin.left;
	uint32_t idvector = gate->ingates.inputs.twin.right;

	uint32_t pos = FindBitLenPositionInVec(gate->gs.avs.bitlen, m_vANDs, m_nNumANDSizes);

	uint32_t startpos = m_vMTIdx[pos] * m_vANDs[pos].bitlen;
	uint32_t nandvals = gate->nvals / gate->gs.avs.bitlen;

	//std::cout << "Bit-length of values in vector gate is " << gate->gs.avs.bitlen << ", nvals = " << gate->nvals <<
	//		", nandvals = " << nandvals << ", mtidx = " << m_vMTIdx[pos] << std::endl;

	//XOR the choice bit onto the D-vector
	m_vD_snd[pos].XORBits((uint8_t*) m_vGates[idchoice].gs.val, m_vMTIdx[pos], nandvals);
 	//m_vD_snd[pos].XORBitNoMask(m_vMTIdx[pos], m_vGates[idchoice].gs.val[0]);

	//std::cout << "choice_val: " << m_vGates[idchoice].gs.val[0] << ", vec_val: " << m_vGates[idvector].gs.val[0] << " (" << gateid << ")" << std::endl;
	//for (uint32_t i = 0, bitstocopy = gate->nvals * m_vANDs[pos].bitlen, ncopiedvals; i < ceil_divide(gate->nvals, GATE_T_BITS); i++, bitstocopy -= GATE_T_BITS) {
	for (uint32_t i = 0, bitstocopy = gate->nvals, ncopiedvals; i < ceil_divide(gate->nvals, GATE_T_BITS); i++, bitstocopy -= GATE_T_BITS, startpos+=GATE_T_BITS) {
		ncopiedvals = std::min(bitstocopy, (uint32_t) GATE_T_BITS);
		//m_vE_snd[pos].XOR(m_vGates[idvector].gs.val[i], m_vMTIdx[pos] * m_vANDs[pos].bitlen, ncopiedvals); //*m_vANDs[pos].bitlen);
		m_vE_snd[pos].XOR(m_vGates[idvector].gs.val[i], startpos, ncopiedvals); //*m_vANDs[pos].bitlen);
#ifdef DEBUGBOOL
		std::cout << "copying from " << m_vMTIdx[pos]*m_vANDs[pos].bitlen << " with len = " << ncopiedvals << std::endl;

		std::cout << "choice-gate " << idchoice << " = " << m_vGates[idchoice].gs.val[0] << " , and vec-gate " << idvector <<
		" = " <<(std::hex) << m_vGates[idvector].gs.val[i] << (std::dec) << std::endl;
#endif
	}
	//m_vMTIdx[pos]++;
	m_vMTIdx[pos]+=nandvals;

	m_vANDGates[pos].push_back(gateid);

	UsedGate(idchoice);
	UsedGate(idvector);
}


inline void BoolSharing::SelectiveOpenOPLUT(uint32_t gateid) {
	GATE *gate = &(m_vGates[gateid]), *ingate;
	uint32_t* input = gate->ingates.inputs.parents;
	uint32_t nparents = gate->ingates.ningates;
	uint32_t typebitlen = sizeof(uint64_t) * 8;
	uint32_t nvals = m_vGates[input[0]].nvals;
	uint32_t outbits = (uint64_t) gate->nvals / nvals;

	uint64_t op_lut_id = (((uint64_t) nparents) << 32) | outbits ;

#ifdef DEBUGBOOL
	std::cout << "Evaluating LUT with " << nparents << " input wires and " << outbits << " output wires" << std::endl;
#endif
	assert(m_vOP_LUT_data.find(op_lut_id) != m_vOP_LUT_data.end());
	op_lut_ctx* lut_ctx = m_vOP_LUT_data.find(op_lut_id)->second;

	//Get the shares on the input wires
	for(uint32_t i = 0; i < nvals; i++) {
		uint64_t selective_opening = 0L;

		//iterate over all parent wires and construct the input gate value
		for(uint32_t j = 0; j < nparents; j++) {
			ingate = &(m_vGates[input[j]]);
			selective_opening |= (((ingate->gs.val[(i/typebitlen)] >> (i%typebitlen)) & 0x01)<<j);
		}
		selective_opening = selective_opening ^ lut_ctx->rot_val->Get<uint64_t>(lut_ctx->sel_opening_ctr * nparents, nparents);
		m_vOP_LUT_SndSelOpeningBuf[op_lut_id]->Set<uint64_t>(selective_opening, m_vOP_LUT_SelOpeningBitCtr[op_lut_id] + i * nparents, nparents);
		lut_ctx->sel_opening_ctr++;
		//std::cout << "Selective opening to be sent: " << selective_opening << std::endl;
	}
	m_vOP_LUT_SelOpeningBitCtr[op_lut_id] += (nparents * nvals);

	m_vOPLUTGates[op_lut_id].push_back(gateid);
#ifdef DEBUGBOOL
	m_vOP_LUT_SndSelOpeningBuf[op_lut_id]->PrintHex();
#endif
}

void BoolSharing::FinishCircuitLayer() {
	//Compute the values of the AND gates
#ifdef DEBUGBOOL
	if(m_nInputShareRcvSize > 0) {
		std::cout << "Received "<< m_nInputShareRcvSize << " input shares: ";
		m_vInputShareRcvBuf.Print(0, m_nInputShareRcvSize);
	}
	if(m_nOutputShareRcvSize > 0) {
		std::cout << "Received " << m_nOutputShareRcvSize << " output shares: ";
		m_vOutputShareRcvBuf.Print(0, m_nOutputShareRcvSize);
	}
#endif

#ifdef DEBUGBOOL
	std::cout << "Evaluating MTs" << std::endl;
#endif
	EvaluateMTs();
#ifdef DEBUGBOOL
	std::cout << "Setting Values of AND Gates" << std::endl;
#endif
	EvaluateANDGate();
#ifdef DEBUGBOOL
	std::cout << "Assigning values to OP-LUT Gates" << std::endl;
#endif
	EvaluateOPLUTGates();
#ifdef DEBUGBOOL
	std::cout << "Assigning Input Shares" << std::endl;
#endif
	AssignInputShares();
#ifdef DEBUGBOOL
	std::cout << "Assigning Output Shares" << std::endl;
#endif
	AssignOutputShares();
#ifdef DEBUGBOOL
	std::cout << "Initializing new layer" << std::endl;
#endif
	InitNewLayer();
}

void BoolSharing::EvaluateMTs() {
	for (uint32_t i = 0; i < m_nNumANDSizes; i++) {
		uint64_t startpos = m_vMTStartIdx[i];
		uint64_t endpos = m_vMTIdx[i];
		if(startpos != endpos) {//do nothing, since len = 0, TODO: there is an error somewhere that makes this check necessary, fix!
			uint64_t len = endpos - startpos;
			uint64_t startposbytes = ceil_divide(startpos, 8);
			uint64_t startposstringbits = startpos * m_vANDs[i].bitlen;
			uint64_t startposstringbytes = startposbytes * m_vANDs[i].bitlen;
			uint64_t lenbytes = ceil_divide(len, 8);
			uint64_t stringbytelen = ceil_divide(m_vANDs[i].bitlen * len, 8);
			uint64_t mtbytelen = ceil_divide(m_vANDs[i].bitlen, 8);


		/*	std::cout << "lenbytes = " << lenbytes << ", stringlen = " << stringbytelen << ", mtbytelen = " << mtbytelen <<
			", startposbytes = " << startposbytes << ", startposstring = " << startposstringbytes << ", nummts: " <<
				m_nNumMTs[i] << ", mtidx = " << m_vMTIdx[i] << ", mtstartidx = " << m_vMTStartIdx[i] << ", numandgates: " <<
				m_vANDs[i].numgates <<std::endl;*/

			m_vD_snd[i].XORBytes(m_vD_rcv[i].GetArr() + startposbytes, startposbytes, lenbytes);
			m_vE_snd[i].XORBytes(m_vE_rcv[i].GetArr() + startposstringbytes, startposstringbytes, stringbytelen);


#ifdef DEBUGBOOL
			if(i > 0) {
				std::cout << "i = " << i << ", lenbytes = " << lenbytes << ", stringlen = " << stringbytelen << ", mtbytelen = " << mtbytelen <<
					", startposbytes = " << startposbytes << ", startposstring = " << startposstringbytes << ", startidx = " <<
					m_vMTStartIdx[i] << ", idx = " << m_vMTIdx[i] << ", num ANDs = " << m_vANDs[i].numgates << ", nummts = " <<
					m_nNumMTs[i] << ", " << m_vMTIdx[i] - m_vMTStartIdx[i] << std::endl;

			std::cout << "A share: ";
			m_vA[i].Print(0, len);
			std::cout << "B share: ";
			m_vB[i].PrintHex(0, stringbytelen);
			std::cout << "C-share: ";
			m_vC[i].PrintHex(0, stringbytelen);

			std::cout << "D-rcv: ";
			m_vD_rcv[i].Print(0,len);
			std::cout << "E-rcv: ";
			m_vE_rcv[i].PrintHex(0, stringbytelen);
			std::cout << "D-total: ";
			m_vD_snd[i].Print(0,len);
			std::cout << "E-total: ";
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
					uint8_t* tmp = (uint8_t*) malloc(ceil_divide(m_vANDs[i].bitlen, 8));
					for (uint32_t j = 0; j < len; j++) {
						if (m_vA[i].GetBitNoMask(j + startpos)) { //a * e
							m_vE_snd[i].GetBits(tmp, startposstringbits + j*m_vANDs[i].bitlen, m_vANDs[i].bitlen);
							m_vResA[i].SetBits(tmp, startposstringbits + j*m_vANDs[i].bitlen, m_vANDs[i].bitlen);
						}
						if (m_vD_snd[i].GetBitNoMask(j + startpos)) { //d * b
							m_vB[i].GetBits(tmp, startposstringbits + j*m_vANDs[i].bitlen, m_vANDs[i].bitlen);
							m_vResB[i].SetBits(tmp, startposstringbits + j*m_vANDs[i].bitlen, m_vANDs[i].bitlen);
						}
					}
					free(tmp);
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
						uint8_t* tmp = (uint8_t*) malloc(ceil_divide(m_vANDs[i].bitlen, 8));
						for (uint32_t j = 0; j < len; j++) {
							if (m_vD_snd[i].GetBitNoMask(j + startpos)) { //d * e
								//uint64_t tmp = m_vE_snd[i].Get<uint64_t>(startposstringbits + j*m_vANDs[i].bitlen, m_vANDs[i].bitlen);
								m_vE_snd[i].GetBits(tmp, startposstringbits + j*m_vANDs[i].bitlen, m_vANDs[i].bitlen);
								//m_vResB[i].Set<uint64_t>(tmp, startposstringbits + j*m_vANDs[i].bitlen, m_vANDs[i].bitlen);
								m_vResB[i].SetBits(tmp, startposstringbits + j*m_vANDs[i].bitlen, m_vANDs[i].bitlen);
								//m_vResB[i].SetBitsPosOffset(m_vE_snd[i].GetArr(), startposstringbits + j * m_vANDs[i].bitlen,
								//		startposstringbits + j * m_vANDs[i].bitlen, m_vANDs[i].bitlen);
							}
						}
						free(tmp);
					}
				}
				m_vResA[i].XORBytes(m_vResB[i].GetArr() + startposstringbytes, startposstringbytes, stringbytelen);
			}
		}
	}
}

void BoolSharing::EvaluateANDGate() {
	GATE* gate;
	for (uint32_t k = 0; k < m_nNumANDSizes; k++) {
		for (uint32_t i = 0, j, bitstocopy, len, idx = m_vMTStartIdx[k]*m_vANDs[k].bitlen; i < m_vANDGates[k].size(); i++) {
			gate = &(m_vGates[m_vANDGates[k][i]]);
			InstantiateGate(gate);

			bitstocopy = gate->nvals;

			for (j = 0; j < ceil_divide(gate->nvals, GATE_T_BITS); j++, bitstocopy -= GATE_T_BITS) {
				len = std::min(bitstocopy, (uint32_t) GATE_T_BITS);

#ifdef DEBUGBOOL
				m_vResA[k].PrintHex();

				std::cout << "setting AND gate " << m_vANDGates[k][i] << " with val-size = " << gate->nvals <<
				", sharinbits = " << gate->sharebitlen << ", and bitstocopy = " << bitstocopy <<
				" to value: " << (std::hex) << m_vResA[k].Get<UGATE_T>(idx, len) << (std::dec) << std::endl;
#endif
				gate->gs.val[j] = m_vResA[k].Get<UGATE_T>(idx, len);
				/*if(k > 0) {
					std::cout << "res_val = " << gate->gs.val[j] << " (" << m_vANDGates[k][i] << ")" <<
							", startpos = " << m_vMTStartIdx[k] << ", idx = " << idx << ", len = " << len << std::endl;
				}*/
				idx += len;
			}
		}

		m_vMTIdx[k] = PadToMultiple(m_vMTIdx[k], 8); //pad mtidx to next byte
		m_vMTStartIdx[k] = m_vMTIdx[k];
	}
}

void BoolSharing::EvaluateOPLUTGates() {
	GATE* gate;
	uint64_t op_lut_id, table_out;
	uint32_t nparents, outbits, nvals, tableid;
	uint32_t* inputs;
	uint32_t gatevalbitlen = sizeof(uint64_t) * 8;

	//Compute the masked table indice and store it in the Receive Buffer for later use
	for(auto it=m_vOP_LUT_SelOpeningBitCtr.begin(); it!=m_vOP_LUT_SelOpeningBitCtr.end(); it++) {
		if(it->second > 0) {
			m_vOP_LUT_RecSelOpeningBuf[it->first]->XORBits(m_vOP_LUT_SndSelOpeningBuf[it->first]->GetArr(), 0, it->second);
#ifdef DEBUGBOOL
			std::cout << "Combined Selective Openings:" <<std::endl;
			m_vOP_LUT_RecSelOpeningBuf[it->first]->PrintHex();
#endif
		}
	}


	for(auto it=m_vOPLUTGates.begin(); it!=m_vOPLUTGates.end(); it++) {
		op_lut_id = it->first;
		uint32_t gatectr = 0;
		uint32_t maskbit_ctr = m_vOP_LUT_data[op_lut_id]->mask_ctr * (1<<m_vOP_LUT_data[op_lut_id]->n_inbits) * m_vOP_LUT_data[op_lut_id]->n_outbits;
		for(uint32_t i = 0; i < it->second.size(); i++) {
			gate = &(m_vGates[it->second[i]]);

			inputs = gate->ingates.inputs.parents;
			nparents = gate->ingates.ningates;
			nvals = m_vGates[inputs[0]].nvals;
			outbits = (uint64_t) gate->nvals / nvals;

			InstantiateGate(gate);

			for(uint32_t n = 0; n < nvals; n++) {
				tableid = m_vOP_LUT_RecSelOpeningBuf[op_lut_id]->Get<uint64_t>(gatectr, nparents);
				table_out = m_vOP_LUT_data[op_lut_id]->table_mask->Get<uint64_t>(maskbit_ctr + tableid * outbits, outbits);
#ifdef DEBUGBOOL
				std::cout << "table output = " << (std::hex) << table_out << " for tableid = " << tableid << (std::dec) << " and ctr+n = " << m_vOP_LUT_data[op_lut_id]->mask_ctr+n << std::endl;
#endif
				for(uint32_t o = 0; o < outbits; o++) {
					gate->gs.val[(o*nvals+n)/gatevalbitlen] |= (((table_out>>o) & 0x01L)<<((o*nvals+n)%gatevalbitlen));
				}
				gatectr+=nparents;
				maskbit_ctr+= ((1<<m_vOP_LUT_data[op_lut_id]->n_inbits) * m_vOP_LUT_data[op_lut_id]->n_outbits);
			}

			m_vOP_LUT_data[op_lut_id]->mask_ctr +=nvals;

			for(uint32_t j = 0; j < nparents; j++) {
				UsedGate(inputs[j]);
			}
			free(inputs);
		}
	}
}


void BoolSharing::AssignInputShares() {
	GATE* gate;
	for (uint32_t i = 0, j, rcvshareidx = 0, bitstocopy, len; i < m_vInputShareGates.size(); i++) {
		gate = &(m_vGates[m_vInputShareGates[i]]);
		InstantiateGate(gate);

		bitstocopy = gate->nvals;
		for (j = 0; j < ceil_divide(gate->nvals, GATE_T_BITS); j++, bitstocopy -= GATE_T_BITS) {
			len = std::min(bitstocopy, (uint32_t) GATE_T_BITS);
			gate->gs.val[j] = m_vInputShareRcvBuf.Get<UGATE_T>(rcvshareidx, len);
#ifdef DEBUGBOOL
			std::cout << "assigned value " << gate->gs.val[j] << " to gate " << m_vInputShareGates[i] << " with nvals = " << gate->nvals << " and sharebitlen = " << gate->sharebitlen << std::endl;
#endif
			rcvshareidx += len;
		}
	}
}

void BoolSharing::AssignOutputShares() {
	GATE* gate;
	for (uint32_t i = 0, j, rcvshareidx = 0, bitstocopy, len, parentid; i < m_vOutputShareGates.size(); i++) {
		gate = &(m_vGates[m_vOutputShareGates[i]]);
		parentid = gate->ingates.inputs.parent;
		InstantiateGate(gate);

		bitstocopy = gate->nvals;
		for (j = 0; j < ceil_divide(gate->nvals, GATE_T_BITS); j++, bitstocopy -= GATE_T_BITS) {
			len = std::min(bitstocopy, (uint32_t) GATE_T_BITS);
			gate->gs.val[j] = m_vGates[parentid].gs.val[j] ^ m_vOutputShareRcvBuf.Get<UGATE_T>(rcvshareidx, len);
#ifdef DEBUGBOOL
			std::cout << "Outshare: " << (std::hex) << gate->gs.val[j] << " = " << m_vGates[parentid].gs.val[j] << " ^ " <<
					m_vOutputShareRcvBuf.Get<UGATE_T>(rcvshareidx, len) << (std::dec) << std::endl;
#endif
			rcvshareidx += len;
		}
		UsedGate(parentid);
	}
}

void BoolSharing::GetDataToSend(std::vector<BYTE*>& sendbuf, std::vector<uint64_t>& sndbytes) {
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
			std::cout << "Sending " << mtbytelen*8 << " multiplication triples" << std::endl;
		}
#endif
	}

	//OP-LUT selective openings
	for(auto it=m_vOP_LUT_SelOpeningBitCtr.begin(); it!=m_vOP_LUT_SelOpeningBitCtr.end(); it++) {
		if(it->second > 0) {
			sendbuf.push_back(m_vOP_LUT_SndSelOpeningBuf[it->first]->GetArr());
			sndbytes.push_back(ceil_divide(it->second, 8));
		}
	}

#ifdef DEBUGBOOL
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

void BoolSharing::GetBuffersToReceive(std::vector<BYTE*>& rcvbuf, std::vector<uint64_t>& rcvbytes) {
	//Input shares
	if (m_nInputShareRcvSize > 0) {
		if (m_vInputShareRcvBuf.GetSize() < ceil_divide(m_nInputShareRcvSize, 8)) {
			m_vInputShareRcvBuf.ResizeinBytes(ceil_divide(m_nInputShareRcvSize, 8));
		}
		rcvbuf.push_back(m_vInputShareRcvBuf.GetArr());
		rcvbytes.push_back(ceil_divide(m_nInputShareRcvSize, 8));
	}

	//Output shares
	if (m_nOutputShareRcvSize > 0) {
		if (m_vOutputShareRcvBuf.GetSize() < ceil_divide(m_nOutputShareRcvSize, 8)) {
			m_vOutputShareRcvBuf.ResizeinBytes(ceil_divide(m_nOutputShareRcvSize, 8));
		}
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

	//OP-LUT selective openings
	for(auto it=m_vOP_LUT_SelOpeningBitCtr.begin(); it!=m_vOP_LUT_SelOpeningBitCtr.end(); it++) {
		if(it->second > 0) {
			rcvbuf.push_back(m_vOP_LUT_RecSelOpeningBuf[it->first]->GetArr());
			rcvbytes.push_back(ceil_divide(it->second, 8));
		}
	}
}

inline void BoolSharing::InstantiateGate(GATE* gate) {
	gate->gs.val = (UGATE_T*) calloc((ceil_divide(gate->nvals, GATE_T_BITS)), sizeof(UGATE_T));
	gate->instantiated = true;
}

void BoolSharing::EvaluateSIMDGate(uint32_t gateid) {
	GATE* gate = &(m_vGates[gateid]);
	uint32_t vsize = gate->nvals;

#ifdef BENCHBOOLTIME
	timespec tstart, tend;
	clock_gettime(CLOCK_MONOTONIC, &tstart);
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
		clock_gettime(CLOCK_MONOTONIC, &tend);
		m_nCombTime += getMillies(tstart, tend);
#endif
		/*std::cout << "Res value = " << (std::hex);
		for(uint64_t i = 0; i < ceil_divide(vsize, GATE_T_BITS); i++) {
			std::cout << gate->gs.val[i] << " ";
		}
		std::cout << (std::dec) << std::endl;*/
		/*for (uint32_t k = 0, bitstocopy = vsize; k < ceil_divide(vsize, GATE_T_BITS); k++, bitstocopy -= GATE_T_BITS) {
			uint32_t size = std::min(bitstocopy, ((uint32_t) GATE_T_BITS));
			gate->gs.val[k] = 0;
			//TODO: not working if valsize of the original gate is greater than GATE_T_BITS!, replace for variable sized function
			for (uint32_t i = 0; i < size; i++) {
				gate->gs.val[k] |= m_vGates[input[i + k * GATE_T_BITS]].gs.val[0] << i;
				UsedGate(input[i + k * GATE_T_BITS]);
			}
		}*/
		for(uint32_t i = 0; i < nparents; i++) {
			UsedGate(input[i]);
		}

		free(input);
	} else if (gate->type == G_SPLIT) {
#ifdef DEBUGSHARING
		std::cout << " which is a SPLIT gate" << std::endl;
#endif
		uint32_t pos = gate->gs.sinput.pos;
		uint32_t idparent = gate->ingates.inputs.parent;
		InstantiateGate(gate);
		//TODO optimize
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
			arraypos = positions[i] >> 6;
			bitpos = positions[i] & 0x3F;
			gate->gs.val[i >> 6] |= (((valptr[arraypos] >> bitpos) & 0x1) << (i & 0x3F));
		}
		UsedGate(idparent);
		if(del_pos)
			free(positions);
#ifdef BENCHBOOLTIME
		clock_gettime(CLOCK_MONOTONIC, &tend);
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
		clock_gettime(CLOCK_MONOTONIC, &tend);
		m_nCombStructTime += getMillies(tstart, tend);
#endif
	}
#ifdef BENCHBOOLTIME
	clock_gettime(CLOCK_MONOTONIC, &tend);
	m_nSIMDTime += getMillies(tstart, tend);
#endif
}

uint32_t BoolSharing::AssignInput(CBitVector& inputvals) {
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

uint32_t BoolSharing::GetOutput(CBitVector& out) {
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

void BoolSharing::PrintPerformanceStatistics() {
	std::cout << "Boolean Sharing: ANDs: ";
	uint64_t total_non_vec_ANDs = 0;
	uint64_t total_vec_ANDs = 0;
	for (uint32_t i = 0; i < m_nNumANDSizes; i++) {
		std::cout << m_vANDs[i].numgates << " (" << m_vANDs[i].bitlen << "-bit) ; ";
		total_non_vec_ANDs += (((uint64_t) m_vANDs[i].numgates ) * ((uint64_t) m_vANDs[i].bitlen));
		total_vec_ANDs += ((uint64_t) m_vANDs[i].numgates);
	}
	std::cout << "Depth: " << GetMaxCommunicationRounds() << std::endl;
	std::cout << "Total Vec AND: " << total_vec_ANDs << std::endl;
	std::cout << "Total Non-Vec AND: " << total_non_vec_ANDs << std::endl;
	std::cout << "XOR vals: "<< m_cBoolCircuit->GetNumXORVals() << " gates: "<< m_cBoolCircuit->GetNumXORGates() << std::endl;
	std::cout << "Comb gates: " << m_cBoolCircuit->GetNumCombGates() << ", CombStruct gates: " <<  m_cBoolCircuit->GetNumStructCombGates() <<
			", Perm gates: "<< m_cBoolCircuit->GetNumPermGates() << ", Subset gates: " << m_cBoolCircuit->GetNumSubsetGates() <<
			", Split gates: "<< m_cBoolCircuit->GetNumSplitGates() << std::endl;
#ifdef BENCHBOOLTIME
	std::cout << "XOR time " << m_nXORTime << ", SIMD time " << m_nSIMDTime << ", Comb time: " << m_nCombTime << ", Comb structurized time: " <<
			m_nCombStructTime << ", Subset time: " << m_nSubsetTime << std::endl;
#endif
}

void BoolSharing::Reset() {
	m_nTotalNumMTs = 0;
	m_nOPLUT_Tables = 0;
	m_nXORGates = 0;

	m_nNumANDSizes = 0;

	for (uint32_t i = 0; i < m_nNumMTs.size(); i++) {
		m_nNumMTs[i] = 0;
	}
	for (uint32_t i = 0; i < m_vMTStartIdx.size(); i++)
		m_vMTStartIdx[i] = 0;
	for (uint32_t i = 0; i < m_vMTIdx.size(); i++)
		m_vMTIdx[i] = 0;
	m_vANDGates.clear();

	m_vInputShareGates.clear();
	m_vOutputShareGates.clear();

	m_nInputShareSndSize = 0;
	m_nOutputShareSndSize = 0;

	m_nInputShareRcvSize = 0;
	m_nOutputShareRcvSize = 0;

	for (uint32_t i = 0; i < m_vA.size(); i++) {
		/**
			Check if the precomputation mode is RAM and phase of reading. If so, the vectors associated
		 	with the MTs are not refreshed or deleted.
		 */
		if(GetPreCompPhaseValue() != ePreCompRAMRead) {
			m_vA[i].delCBitVector();
			m_vB[i].delCBitVector();
			m_vC[i].delCBitVector();
			m_vS[i].delCBitVector();
		}
		m_vD_snd[i].delCBitVector();
		m_vE_snd[i].delCBitVector();
		m_vD_rcv[i].delCBitVector();
		m_vE_rcv[i].delCBitVector();
		m_vResA[i].delCBitVector();
		m_vResB[i].delCBitVector();
	}
#ifdef USE_KK_OT_FOR_MT
		m_vKKA[0].delCBitVector();
		m_vKKB[0].delCBitVector();
		m_vKKC[0].delCBitVector();
#endif

	m_vInputShareSndBuf.delCBitVector();
	m_vOutputShareSndBuf.delCBitVector();

	m_vInputShareRcvBuf.delCBitVector();
	m_vOutputShareRcvBuf.delCBitVector();

	m_cBoolCircuit->Reset();

	//Reset the OP-LUT data structures
	if(!m_vOP_LUT_data.empty()) {
		std::cout << "Doing the deletion" << std::endl;
		for (auto it=m_vOP_LUT_data.begin(); it!=m_vOP_LUT_data.end(); it++) {
			free(it->second);
		}
		m_vOP_LUT_data.clear();
	}
	if(!m_vOP_LUT_SndSelOpeningBuf.empty()) {
		for (auto it=m_vOP_LUT_SndSelOpeningBuf.begin(); it!=m_vOP_LUT_SndSelOpeningBuf.end(); it++) {
			it->second->delCBitVector();
		}
		m_vOP_LUT_SndSelOpeningBuf.clear();
	}
	if(!m_vOP_LUT_RecSelOpeningBuf.empty()) {
		for (auto it=m_vOP_LUT_RecSelOpeningBuf.begin(); it!=m_vOP_LUT_RecSelOpeningBuf.end(); it++) {
			it->second->delCBitVector();
		}
		m_vOP_LUT_RecSelOpeningBuf.clear();
	}
	if(!m_vOP_LUT_SelOpeningBitCtr.empty()) {
		m_vOP_LUT_SelOpeningBitCtr.clear();
	}

	/**Checking the role and and deciding upon the file to be deleted if the precomputation values are
	  completely used up in a Precomputation READ mode.*/
	filesystem::path precomputation_file;
	if(m_eRole == SERVER) {
		precomputation_file = "pre_comp_server.dump";
	} else {
		precomputation_file = "pre_comp_client.dump";
	}
	if (filesystem::exists(precomputation_file)
		&& (m_nFilePos >= filesystem::file_size(precomputation_file))
		&& (GetPreCompPhaseValue() == ePreCompRead)) {
		filesystem::remove(precomputation_file);
		m_nFilePos = -1;	// FIXME: m_nFilePos is unsigned ...
	}

}

/**Pre-computations*/
void BoolSharing::PreComputationPhase() {

	/**Obtaining the precomputation mode value*/
	ePreCompPhase phase_value = GetPreCompPhaseValue();

	/**Decision of the precomputation file based on the role of executor.*/
	filesystem::path filename;
	if(m_eRole == SERVER) {
		filename = "pre_comp_server.dump";
	} else {
		filename = "pre_comp_client.dump";
	}

	/**Check if the precomputation mode is in RAM Reading phase*/
	if(phase_value == ePreCompRAMRead) {
		return;
	}
	/**Check if the execution is non-Read mode or if the file to be used in READ mode doesn't exist*/
	else if((phase_value != ePreCompRead)||(!filesystem::exists(filename))) {
		/**Compute the MTs normally*/
		ComputeMTs();
		/**Check if the mode of precomputation is store. If so store it to respective file.*/
		if(phase_value == ePreCompStore) {
			StoreMTsToFile(filename.c_str());
		}
		/**
			Check if precompution mode is in RAM writing phase. If so, change it to RAM reading phase
			since, the write phase mainly comprises of computation of MTs in their respective vectors.
		*/
		else if(phase_value == ePreCompRAMWrite) {
			SetPreCompPhaseValue(ePreCompRAMRead);
		}
	}
	/**This condition is activated once READ mode is persistent and execution of the mode is possible.*/
	else {
		ReadMTsFromFile(filename.c_str());
	}
}

void BoolSharing::StoreMTsToFile(const char *filename) {


	FILE *fp;

	/**
		Condition to check if the file already exists. If so then, the mode of write would
		be file append.
	*/
	if(filesystem::exists(filename)) {
		fp = fopen(filename, "a+b");
	}
	else {
		fp = fopen(filename, "wb");
	}

	/**Initially writing the NUMANDSizes corresponding to the number of AND gate Vectors.*/
	fwrite(&m_nNumANDSizes, sizeof(uint32_t), 1, fp);

	/**Writing the MTs and bytelen of the MTs o the file.*/
	for (uint32_t i = 0; i < m_nNumANDSizes; i++) {
		uint32_t andbytelen = ceil_divide(m_nNumMTs[i], 8);
		// uint32_t stringbytelen = ceil_divide(m_nNumMTs[i] * m_vANDs[i].bitlen, 8);
		fwrite(&andbytelen, sizeof(uint32_t), 1, fp);
		fwrite(m_vA[i].GetArr(), andbytelen, 1, fp);
		fwrite(m_vB[i].GetArr(), andbytelen, 1, fp);
		fwrite(m_vC[i].GetArr(), andbytelen, 1, fp);

	}
	/**Closing the file pointer.*/
	fclose(fp);
}

void BoolSharing::ReadMTsFromFile(const char *filename) {

	FILE *fp;
	// /**Calculate the file size*/
	// uint64_t file_size = filesystem::file_size(filename);

	/**Variable for the storing the NUMANDSizes value from the file.*/
	uint32_t num_and_sizes;

	/**Opening the file in read mode.*/
	fp = fopen(filename, "rb");
	/**BYTE pointer used as a buffer to read from the file.*/
	BYTE *ptr;
	/**Seek the file pointer to the location of the last read position.*/
	if(fseek(fp, m_nFilePos, SEEK_SET))
            std::cout << "Error occured in fseek" << std::endl;
	/**Reading the num and sizes from the file.*/
	if(!fread(&num_and_sizes, sizeof(uint32_t), 1, fp))
            std::cout << "Error occured in fread" << std::endl;;
	for (uint32_t i = 0; i < m_nNumANDSizes; i++) {

		/**Calculating the required ANDGatelength in bytes for the provided circuit configuration.*/
		uint32_t andbytelen = ceil_divide(m_nNumMTs[i], 8);
		uint32_t org_andbytelen;
		uint32_t stringbytelen = ceil_divide(m_nNumMTs[i] * m_vANDs[i].bitlen, 8);

		/**Reading the ANDGate length in bytes from file.*/
		if(!fread(&org_andbytelen, sizeof(uint32_t), 1, fp))
                    std::cout << "Error occured in fread" << std::endl;

		/**Allocating the memory for the BYTE pointer with the read ANDGate lenght size from the file.*/
		ptr = (BYTE*)malloc(org_andbytelen*sizeof(BYTE));

		/**
			If unequal means the bytes should be read from the file with original byte size else if
			the configured size.
		*/
		if(org_andbytelen != andbytelen) {

			if(!fread(ptr, org_andbytelen, 1, fp))
                            std::cout << "Error occured in fread" << std::endl;
			m_vA[i].Copy(ptr, 0, andbytelen);
			if(!fread(ptr, org_andbytelen, 1, fp))
                            std::cout << "Error occured in fread" << std::endl;
			m_vB[i].Copy(ptr, 0, andbytelen);
			if(!fread(ptr, org_andbytelen, 1, fp))
                                std::cout << "Error occured in fread" << std::endl;
			m_vC[i].Copy(ptr, 0, andbytelen);
		}
		else {
			if(!fread(ptr, andbytelen, 1, fp))
                            std::cout << "Error occured in fread" << std::endl;
			m_vA[i].Copy(ptr, 0, andbytelen);
			if(!fread(ptr, andbytelen, 1, fp))
                                std::cout << "Error occured in fread" << std::endl;
			m_vB[i].Copy(ptr, 0, andbytelen);
			if(!fread(ptr, andbytelen, 1, fp))
                            std::cout << "Error occured in fread" << std::endl;
			m_vC[i].Copy(ptr, 0, andbytelen);
		}
		m_vD_snd[i].Copy(m_vA[i].GetArr(), 0, andbytelen);
		m_vE_snd[i].Copy(m_vB[i].GetArr(), 0, stringbytelen);

	}

	/**Storing the current file pointer position for next iteration use of the circuit setup.*/
	m_nFilePos = ftell(fp);
	/**Closing the file.*/
	fclose(fp);
}

BOOL BoolSharing::isCircuitSizeLessThanOrEqualWithValueFromFile(char *filename, uint32_t in_circ_size) {

	/**Check if the file already exists and if the existing is empty. If so, return false.*/
	if(!filesystem::exists(filename)||filesystem::is_empty(filename)) {
		/**Returning false and reverting the precomputation mode to default.*/
		return FALSE;
	}

	/**Opening the precomputation file in read mode.*/
	FILE *fp = fopen(filename, "rb");

	uint32_t circ_size_in_file, andbytelen_in_file;

	/**Reading the circuit size mainly the NUMAndGate vector size*/
	if(!fread(&circ_size_in_file, sizeof(uint32_t), 1, fp))
            std::cout << "Error occured in fread" << std::endl;
	/**Checking if they are unequal.*/
	if(circ_size_in_file != in_circ_size) {
		/**Returning false and reverting the precomputation mode to default.*/
		return FALSE;
	}
	/**
	 Checking the byte length of the MTs in the file with the required size.
	 If it is value in the file is less than the required then, the precomputation
	 mode is reverted to defaut.
	*/
	for (uint32_t i = 0; i < circ_size_in_file; i++) {
		/**Calculating the AND gate length in bytes for the provided circuit configuration.*/
		uint32_t andbytelen = ceil_divide(m_nNumMTs[i], 8);
		/**Reading the AND gate length in bytes from the file.*/
		if(!fread(&andbytelen_in_file, sizeof(uint32_t), 1, fp))
                    std::cout << "Error occured in fread" << std::endl;
		uint32_t traverseMT_size_in_file = andbytelen_in_file*3;

		/**Shifting through the MTs based on the ANDGate size in byte length.*/
		fseek(fp, (ftell(fp) + traverseMT_size_in_file), SEEK_SET);

		/**Checking if the condition of size of byte length in file is lower than byte length required.*/
		if(andbytelen > andbytelen_in_file) {

			/**Close the file*/
			fclose(fp);
			/**Returning false and reverting the precomputation mode to default.*/
			return FALSE;
		}
	}
	/**Close the file*/
	fclose(fp);
	return TRUE;
}
