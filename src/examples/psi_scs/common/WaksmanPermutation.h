/**
 \file 		WaksmanPermutation.h
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
 \brief		Implementation of WaksmanPermutation
 */
#ifndef __ABY_WAKSMANPERMUTATION_H_
#define __ABY_WAKSMANPERMUTATION_H_

#include <vector>
#include <iostream>
#include "stdio.h"
#include <stdlib.h>
#include "../../../abycore/circuit/booleancircuits.h"

using namespace std;

uint32_t estimateGates(uint32_t numGates);
//TODO: Generate destructor methods

//Some default output that is used if no output is written to
static vector<vector<uint32_t> > NON_INIT_DEF_OUTPUT;

class PermutationNetwork {
	//double linked list; node n is head
	class TodoList {
		uint32_t* nextu;
		uint32_t* prevu;
		uint32_t n;

	public:
		void remove(uint32_t x) {
			nextu[prevu[x]] = nextu[x];
			prevu[nextu[x]] = prevu[x];
		}

		uint32_t next() {
			uint32_t ret = nextu[n];
			if (ret == n)
				return -1;
			else
				return ret;
		}

		TodoList(uint32_t num) {
			n = num;
			nextu = (uint32_t*) malloc(sizeof(uint32_t) * (n + 1)); //new uint32_t[n+1];
			prevu = (uint32_t*) malloc(sizeof(uint32_t) * (n + 1)); //new uint32_t[n+1];
			for (uint32_t i = 0; i < n + 1; i++) {
				nextu[i] = (i + 1) % (n + 1);
				prevu[i] = (i + n) % (n + 1);
			}
		}
	};

	class WaksmanPermutation {
	public:
		WaksmanPermutation* b1;
		WaksmanPermutation* b2;

		uint32_t m_nNumInputs;
		uint32_t m_nSizeB2;

		WaksmanPermutation(uint32_t numgates, PermutationNetwork* pm);
		virtual ~WaksmanPermutation();
		//Program the permutation
		void program(uint32_t* perm);
		void program_rec(uint32_t in, uint32_t block, uint32_t* p1, uint32_t* p2, uint32_t* rows, uint32_t* cols);
		vector<vector<uint32_t> > generateCircuit(vector<vector<uint32_t> > inputs, vector<vector<uint32_t> > outputs);

		vector<uint32_t> s1, s2;
		TodoList* Todo;
		PermutationNetwork* m_PM;
	};

public:
	PermutationNetwork(uint32_t size, BooleanCircuit* circ) {
		m_nNum = size;
		gatebuildcounter = 0;
		m_cBoolCirc = circ;
		m_vSwitchGateProgram.resize(estimateGates(size));
		wm = new WaksmanPermutation(size, this);
	}

	uint32_t nextGate() {
		return gatebuildcounter++;
	}
	uint32_t getSwapGateAt(uint32_t idx) {
		return m_vSwapGates[idx];
	}
	void setSwitchProgram(uint32_t idx, bool val) {
		m_vSwitchGateProgram[idx] = val;
	}

	void setPermutationGates(vector<uint32_t>& gates) {
		m_vSwapGates = gates;
	}
	vector<vector<uint32_t> > buildPermutationCircuit(vector<vector<uint32_t> >& input) {
		return wm->generateCircuit(input, NON_INIT_DEF_OUTPUT);
	}
	vector<vector<uint32_t> > PutCondSwapGate(vector<uint32_t>& a, vector<uint32_t>& b, uint32_t s) {
		return m_cBoolCirc->PutCondSwapGate(a, b, s, true);
	}
	vector<bool> ProgramPermutationNetwork(uint32_t* permutation) {
		wm->program(permutation);
		return m_vSwitchGateProgram;
	}

private:
	uint32_t gatebuildcounter;
	uint32_t m_nNum;
	vector<bool> m_vSwitchGateProgram; //contains the actual program for the swapgates to achieve the output permutation
	vector<uint32_t> m_vSwapGates; //contains the gate addresses of the swapgates
	WaksmanPermutation* wm;
	BooleanCircuit* m_cBoolCirc;

};

#endif /* __ABY_WAKSMANPERMUTATION_H_ */
