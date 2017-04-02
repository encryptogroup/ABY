/**
 \file 		lowmccircuit.h
 \author 	michael.zohner@ec-spride.de
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
 \brief		Implementation of LowMCCiruit
 */
#ifndef __LOWMCCIRCUIT_H_
#define __LOWMCCIRCUIT_H_

#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/aby/abyparty.h"
#include "../../../abycore/util/cbitvector.h"
#include "../../../abycore/util/typedefs.h"
#include "../../../abycore/util/graycode.h"
#include <cassert>

static const BYTE mpccseed[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

/* versions of the lowmc cipher: short term security, short term wide, long term security, long term wide */
enum LowMCVersion {
	STLowMC = 0, LTLowMC = 1
};

struct LowMCParams {
	uint32_t nsboxes;
	uint32_t keysize;
	uint32_t blocksize;
	uint32_t data;
	uint32_t nrounds;
};

struct matmul {
	UGATE_T** matrix;
	uint32_t column;
};

//parameters: sboxes (m), key-length (k), statesize (n), data (d), rounds (r)
static const LowMCParams stp = { 49, 80, 256, 64, 12 };
static const LowMCParams ltp = { 63, 128, 256, 128, 14 };

static const LowMCParams lowmcparamlookup[] = { stp, ltp};

static uint32_t m_nRndCtr;
static CBitVector m_vRandomBits;
static code* m_tGrayCode;
static uint32_t m_nZeroGate;

int32_t test_lowmc_circuit(e_role role, char* address, uint16_t port, uint32_t nvals, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, uint32_t statesize, uint32_t keysize,
		uint32_t sboxes, uint32_t rounds, uint32_t maxnumgates, crypto* crypt);
int32_t test_lowmc_circuit(e_role role, char* address, uint16_t port, uint32_t nvals, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, LowMCParams* param, uint32_t maxgates,
		crypto* crypt);
share* BuildLowMCCircuit(share* val, share* key, BooleanCircuit* circ, LowMCParams* param, uint32_t zerogate, crypto* crypt);
void LowMCAddRoundKey(vector<uint32_t>& val, vector<uint32_t> key, uint32_t locmcstatesize, uint32_t round, BooleanCircuit* circ);
void LowMCMultiplyState(vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ);
void LowMCXORConstants(vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ);
void LowMCXORMultipliedKey(vector<uint32_t>& state, vector<uint32_t> key, uint32_t lowmcstatesize, uint32_t round, BooleanCircuit* circ);
void LowMCPutSBoxLayer(vector<uint32_t>& input, uint32_t numsboxes, BooleanCircuit* circ);
void LowMCPutSBox(uint32_t& o1, uint32_t& o2, uint32_t& o3, BooleanCircuit* circ);

void LowMCMultiplyStateCallback(vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ);
void CallbackMultiplication(GATE* gate, void* matmulinfos);
void CallbackBuild4RMatrixAndMultiply(GATE* gate, void* matrix);
void CallbackMultiplyAndDestroy4RMatrix(GATE* gate, void* matrix);


void FourRussiansMatrixMult(vector<uint32_t>& state, uint32_t lowmcstatesize, BooleanCircuit* circ);

#endif /* __LOWMCCIRCUIT_H_ */
