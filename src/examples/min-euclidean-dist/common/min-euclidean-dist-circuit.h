/**
 \file 		min-euclidean-dist-circuit.h
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
 \brief		Implementation of Minimum Euclidean Distance Circuit
 */

#ifndef __MIN_EUCL_DIST_H_
#define __MIN_EUCL_DIST_H_

#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include <cassert>
#include <vector>

class BooleanCircuit;

uint64_t verify_min_euclidean_dist(uint32_t** serverdb, uint32_t* clientquery, uint32_t dbsize, uint32_t dim);
int32_t test_min_eucliden_dist_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t dbsize, uint32_t dim,
		uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing dstsharing, e_sharing minsharing, ePreCompPhase pre_comp_value);
share* build_min_euclidean_dist_circuit(share*** S, share** C, uint32_t n, uint32_t d, share** Ssqr, share* Csqr,
		Circuit* distcirc, BooleanCircuit* mincirc, std::vector<Sharing*>& sharings, e_sharing minsharing);


#endif /* __MIN_EUCL_DIST_H_ */
