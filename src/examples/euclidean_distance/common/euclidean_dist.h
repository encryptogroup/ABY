/**
 \file 		euclidean_dist.h
 \author 	sreeram.sadasivam@cased.de
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
 \brief		Implementation of the Euclidean Distance using ABY Framework.
 */

#ifndef __EUCLIDEAN_DIST_H_
#define __EUCLIDEAN_DIST_H_

#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/circuit/arithmeticcircuits.h"
#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include <math.h>
#include <cassert>

/**
 \param		role 		role played by the program which can be server or client part.
 \param 	address 	IP Address
 \param 	seclvl 		Security level
 \param 	nvals		number of values
 \param 	bitlen		Bit Length
 \param 	nthreads	nthreads
 \param		mt_alg		_________
 \param 	sharing		sharing type object
 \brief		This function is used for running a testing environment for finding the
 Euclidean Distance.
 */
int32_t test_euclid_dist_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t nvals, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing sharing);

/**
 \param		s_x1		shared object of first coordinate x1.
 \param		s_y1 		shared object of first coordinate y1.
 \param		s_x2		shared object of first coordinate x2.
 \param		s_y2 		shared object of first coordinate y2.

 \param		bc	 		boolean circuit object.
 \brief		This function is used to build and find the Euclidean Distance (without computing the sqrt at the end).
 */
share* BuildEuclidDistanceCircuit(share *s_x1, share *s_x2, share *s_y1,
		share *s_y2, BooleanCircuit *bc);

#endif /* __EUCLIDEAN_DIST_H_ */
