/**
 \file 		threshold-euclidean-dist.cpp
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
#include "threshold-euclidean-dist.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/sharing/sharing.h"
#include <ENCRYPTO_utils/crypto/crypto.h>

int32_t test_min_eucliden_dist_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t operationbitlen,
        uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing dstsharing, e_sharing minsharing, uint32_t n, bool only_yao) {

    uint64_t * output;
    ABYParty* party = new ABYParty(role, address, port, seclvl, operationbitlen, nthreads, mt_alg);
    std::vector<Sharing*>& sharings = party->GetSharings();

    uint64_t* x1 = new uint64_t[n];
    uint64_t* x2 = new uint64_t[n];
    uint64_t* y1 = new uint64_t[n];
    uint64_t* y2 = new uint64_t[n];

    Circuit *arithcirc, *yaocirc;

    share *s_x1, *s_x2, *s_y1, *s_y2;

    uint32_t input_length = operationbitlen / 4;

    srand(time(NULL));

    uint64_t t; ///< threshold
    if(operationbitlen == 64) {
        t = (uint64_t) rand();
    } else { //operationbitlen == 32
        t = rand() % ((uint64_t) 1 << operationbitlen);
    }

    for (uint32_t i = 0; i < n; i++) {
        x1[i] = rand() % ((uint64_t) 1 << input_length);
        x2[i] = rand() % ((uint64_t) 1 << input_length);
        y1[i] = rand() % ((uint64_t) 1 << input_length);
        y2[i] = rand() % ((uint64_t) 1 << input_length);
    }

    yaocirc = sharings[minsharing]->GetCircuitBuildRoutine();
    arithcirc = only_yao ? yaocirc : sharings[dstsharing]->GetCircuitBuildRoutine();

    if (role == SERVER) {
        s_x1 = arithcirc->PutSIMDINGate(n, x1, input_length, role);
        s_y1 = arithcirc->PutSIMDINGate(n, y1, input_length, role);
        s_x2 = arithcirc->PutDummySIMDINGate(n, input_length);
        s_y2 = arithcirc->PutDummySIMDINGate(n, input_length);
    } else {
        s_x1 = arithcirc->PutDummySIMDINGate(n, input_length);
        s_y1 = arithcirc->PutDummySIMDINGate(n, input_length);
        s_x2 = arithcirc->PutSIMDINGate(n, x2, input_length, role);
        s_y2 = arithcirc->PutSIMDINGate(n, y2, input_length, role);
    }

    share * dst = build_min_euclidean_dist_circuit(s_x1, s_y1, s_x2, s_y2, n, t,
            operationbitlen, arithcirc, (BooleanCircuit*) yaocirc, only_yao);

    dst = yaocirc->PutOUTGate(dst, SERVER);

    party->ExecCircuit();

    if(role == SERVER){
        dst->get_clear_value_vec(&output, &operationbitlen, &n);
        verify_min_euclidean_dist(x1, x2, y1, y2, output, n, t);
    }

    delete x1;
    delete x2;
    delete y1;
    delete y2;

    return 0;
}

//Build_

share* build_min_euclidean_dist_circuit(share* x1, share* y1, share* x2, share* y2,
        uint32_t n, uint64_t t, uint32_t bitlen, Circuit* distcirc, BooleanCircuit* mincirc,
        bool only_yao) {
    uint64_t _one = 1, _zero = 0;

    share * s_dx, *s_dy, *distance;

    // v Constants v
    share * s_t = mincirc->PutSIMDCONSGate(n, t, bitlen);
    share * s_one = mincirc->PutSIMDCONSGate(n, _one, bitlen);
    share * s_zero = mincirc->PutSIMDCONSGate(n, _zero, bitlen);
    // ^ Constants ^
    
    // (a - b)^2 = ! a^2 - 2*a*b + b^2 !
    share* s_x_one_two = distcirc->PutMULGate(x1, x2);
    s_dx = distcirc->PutADDGate(distcirc->PutMULGate(x1, x1), distcirc->PutMULGate(x2, x2));
    s_dx = distcirc->PutSUBGate(s_dx, distcirc->PutADDGate(s_x_one_two, s_x_one_two));

    share* s_y_one_two = distcirc->PutMULGate(y1, y2);
    s_dy = distcirc->PutADDGate(distcirc->PutMULGate(y1, y1), distcirc->PutMULGate(y2, y2));
    s_dy = distcirc->PutSUBGate(s_dy, distcirc->PutADDGate(s_y_one_two, s_y_one_two));

    //d = d_x + d_y = (x_1 - x_2)^2 + (y_1 - y_2)^2
    distance = distcirc->PutADDGate(s_dx, s_dy);

    if (!only_yao)
        distance = mincirc->PutA2YGate(distance);

    share * gt = mincirc->PutGTGate(distance, s_t);
    distance = mincirc->PutMUXGate(s_one, s_zero, gt);

    return distance;
}

void verify_min_euclidean_dist(uint64_t* x1, uint64_t* x2, uint64_t* y1,
        uint64_t* y2, uint64_t * res, uint32_t n, uint64_t t) {
    uint32_t c = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint64_t d = (x1[i] - x2[i])*(x1[i] - x2[i])+(y1[i] - y2[i])*(y1[i] - y2[i]);
        d = d > t ? 1 : 0;
        if (d != res[i]) {
            c++;
            std::cout <<"I#" << i << " x1:" << x1[i] << " x2:" << x2[i] << " y1:" << y1[i] <<
                " y2:" << y2[i] << std::endl;
            std::cout << "Expected " << d << ", but got " << res[i] << std::endl;
        }
    }
    std::cout << c << " wrong results" << std::endl;
}
