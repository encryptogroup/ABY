/**
 \file 		threshold-euclidean-dist.h
 \author	michael.zohner@ec-spride.de
 \author	oleksandr.tkachenko@crisp-da.de
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
 \brief		2D SIMD Threshold Euclidean distance Test class implementation.
 *              Implements the functionality from PST’15 (http://ieeexplore.ieee.org/document/7232947/).
 */

#ifndef __MIN_EUCL_DIST_H_
#define __MIN_EUCL_DIST_H_

#define BIT_LENGTH 32

#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include <cassert>

class BooleanCircuit;

//void verify_min_euclidean_dist(uint32_t* x1, uint32_t* x2, uint32_t* y1,
//        uint32_t* y2, uint32_t * res, uint32_t n, uint32_t t);
void verify_min_euclidean_dist(uint64_t* x1, uint64_t* x2, uint64_t* y1,
        uint64_t* y2, uint64_t * res, uint32_t n, uint64_t t);
int32_t test_min_eucliden_dist_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t operationbitlen,
		uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing dstsharing, e_sharing minsharing, uint32_t n, bool only_yao);
share* build_min_euclidean_dist_circuit(share* x1, share* y1, share* x2, share* y2,
        uint32_t n, uint64_t t, uint32_t bitlen, Circuit* distcirc, BooleanCircuit* mincirc,
        bool only_yao);


#endif /* __MIN_EUCL_DIST_H_ */
