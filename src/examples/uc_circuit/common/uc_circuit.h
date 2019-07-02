/**
 \file 		uc_gate_test.cpp
 \author	kiss@encrypto.cs.tu-darmstadt.de
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
 \brief		Test the universal circuit evaluation
 */

#ifndef __UCCIRCUIT_H_
#define __UCCIRCUIT_H_

//Utility libs
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
//ABY Party class
#include "../../../abycore/aby/abyparty.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/sharing/sharing.h"

#include <assert.h>
#include <iostream>

bool calculate(uint8_t arity, uint32_t input1, uint32_t input2, uint32_t function_number, std::vector<bool> wires_carry);
void eval_UC(std::string circuit, std::string program, std::vector<bool>& input_list, std::vector<bool>& output_list);

int32_t test_universal_circuit(e_role role, char* address, uint16_t port, seclvl seclvl,
		uint32_t nvals, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing sharing, const std::string filename, const std::string p1filename);

#endif /* __UCCIRCUIT_H_ */
