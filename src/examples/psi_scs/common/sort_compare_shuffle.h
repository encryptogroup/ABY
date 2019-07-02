/**
 \file 		abysetintersection.h
 \author 	michael.zohner@ec-spride.de
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
 \brief		Implementation of ABYSetIntersection.
 */
#ifndef __SORT_COMPARE_SHUFFLE_
#define __SORT_COMPARE_SHUFFLE_

#include "WaksmanPermutation.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/circuit/arithmeticcircuits.h"
#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include <cassert>

int32_t test_psi_scs_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t nvals, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg,
		uint32_t prot_version, bool verify);
vector<uint32_t> BuildSCSPSICircuit(share** shr_srv_set, share** shr_cli_set, vector<uint32_t> shr_sel_bits,
		uint32_t neles, uint32_t bitlen, BooleanCircuit* bc, BooleanCircuit* yc, uint32_t type);
vector<uint32_t> PutVectorBitonicSortGate(share** srv_set, share** cli_set, uint32_t neles,
		uint32_t bitlen, BooleanCircuit* circ);
vector<uint32_t> PutDupSelect3Gate(vector<uint32_t>& x1, vector<uint32_t>& x2,
		vector<uint32_t>& x3, BooleanCircuit* circ);
vector<uint32_t> PutDupSelect2Gate(vector<uint32_t>& x1, vector<uint32_t>& x2,
		BooleanCircuit* circ);
vector<uint32_t> PutVectorCondSwapGate(uint32_t a, uint32_t b, uint32_t s,
		BooleanCircuit* circ);

#endif /* __SORT_COMPARE_SHUFFLE_ */
