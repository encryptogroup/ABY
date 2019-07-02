/**
 \file 		WaksmanPermutation.cpp
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
#include "WaksmanPermutation.h"

PermutationNetwork::WaksmanPermutation::~WaksmanPermutation() {
	// TODO Auto-generated destructor stub
}

uint32_t estimateGates(uint32_t numGates) {
	if (numGates == 1){
		return 0;
	}
	else {
		uint32_t s1count = numGates / 2;
		uint32_t s2count = (numGates % 2 == 0) ? numGates / 2 - 1 : numGates / 2;
		return (s1count + s2count) + estimateGates(numGates / 2) + estimateGates(numGates - (numGates / 2));
	}
}

void PermutationNetwork::WaksmanPermutation::program_rec(uint32_t in, uint32_t block, uint32_t* p1, uint32_t* p2, uint32_t* rows, uint32_t* cols) {
	uint32_t out = rows[in];

	if ((in ^ 1) < m_nNumInputs && rows[in ^ 1] != UINT_MAX) {
		m_PM->setSwitchProgram(s1[in / 2], (block == 0) != (in % 2 == 0));
		Todo->remove(in / 2);
	}

	if (block == 1) {
		p2[in / 2] = out / 2;
		if (out / 2 < m_nSizeB2) {
			m_PM->setSwitchProgram(s2[out / 2], out % 2 == 0);
		}
	} else { // block==0
		p1[in / 2] = out / 2;
		if (out / 2 < m_nSizeB2) {
			m_PM->setSwitchProgram(s2[out / 2], out % 2 == 1);
		}
	}
	rows[in] = UINT_MAX;
	cols[out] = UINT_MAX;

	uint32_t newout = out ^ 1;
	if (newout < m_nNumInputs && cols[newout] != UINT_MAX) {
		uint32_t newin = cols[newout];
		cols[newout] = UINT_MAX;
		program_rec(newin, block ^ 1, p1, p2, rows, cols);
	}

	if ((in ^ 1) < m_nNumInputs && rows[in ^ 1] != UINT_MAX) {
		program_rec(in ^ 1, block ^ 1, p1, p2, rows, cols);
	}
}

void PermutationNetwork::WaksmanPermutation::program(uint32_t* perm) {
	if (m_nNumInputs == 1)
		return;

	uint32_t* rows = perm;

	uint32_t* cols = (uint32_t*) malloc(sizeof(uint32_t) * m_nNumInputs); //new uint32_t[v];
	for (uint32_t i = 0; i < m_nNumInputs; i++) {
		uint32_t x = perm[i];
		cols[x] = i;
	}

	// programs for sub-blocks
	uint32_t* p1 = (uint32_t*) malloc(sizeof(uint32_t) * (m_nNumInputs / 2)); //new uint32_t[u / 2];
	uint32_t* p2 = (uint32_t*) malloc(sizeof(uint32_t) * (m_nNumInputs - (m_nNumInputs / 2))); //new uint32_t[u - (u / 2)];

	Todo = new TodoList(m_nNumInputs / 2);
	if (m_nNumInputs % 2 == 1) { // case c+d and b+d
		program_rec(m_nNumInputs - 1, 1, p1, p2, rows, cols);
		if (cols[m_nNumInputs - 1] != UINT_MAX)
			program_rec(cols[m_nNumInputs - 1], 1, p1, p2, rows, cols);
	}

	if (m_nNumInputs % 2 == 0) { // case a
		if (cols[m_nNumInputs - 1] != UINT_MAX)
			program_rec(cols[m_nNumInputs - 1], 1, p1, p2, rows, cols);
		if (cols[m_nNumInputs - 2] != UINT_MAX)
			program_rec(cols[m_nNumInputs - 2], 0, p1, p2, rows, cols);
	}

	for (uint32_t n = Todo->next(); n != UINT_MAX; n = Todo->next()) {
		program_rec(2 * n, 0, p1, p2, rows, cols);
	}

	// program sub-blocks
	b1->program(p1);
	b2->program(p2);
}

PermutationNetwork::WaksmanPermutation::WaksmanPermutation(uint32_t numinputs, PermutationNetwork* pm) {
	m_nNumInputs = numinputs;
	m_PM = pm;

	if (numinputs != 1) {
		// first row X
		s1.resize(m_nNumInputs / 2);

		for (uint32_t i = 0; i < m_nNumInputs / 2; i++)
			s1[i] = pm->nextGate();

		//assign wires to X gates and permute them

		// B1
		b1 = new WaksmanPermutation(numinputs / 2, pm);

		// B2
		b2 = new WaksmanPermutation(numinputs - (numinputs / 2), pm);

		// last row X
		m_nSizeB2 = (numinputs % 2 == 0) ? numinputs / 2 - 1 : numinputs / 2;
		s2.resize(m_nSizeB2);
		for (uint32_t i = 0; i < m_nSizeB2; i++)
			s2[i] = pm->nextGate();

	}

}

vector<vector<uint32_t> > PermutationNetwork::WaksmanPermutation::generateCircuit(vector<vector<uint32_t> > inputs, vector<vector<uint32_t> > outputs) {
	uint32_t rep = inputs[0].size();
	if (outputs == NON_INIT_DEF_OUTPUT) {
		outputs.resize(m_nNumInputs);
		for (uint32_t i = 0; i < m_nNumInputs; i++) {
			outputs[i].resize(rep);
		}
	}
	// wire input to all outputs
	if (m_nNumInputs == 1) {
		for (uint32_t i = 0; i < rep; i++)
			outputs[0][i] = inputs[0][i];
		return outputs;
	}

	uint32_t sizeB2 = m_nNumInputs - (m_nNumInputs / 2);
	vector<vector<uint32_t> > in_p1(m_nNumInputs / 2);
	vector<vector<uint32_t> > in_p2(sizeB2);

	// first row X
	vector<vector<uint32_t> > outtmp(2);
	//outtmp[0].resize(rep);
	//outtmp[1].resize(rep);
	for (uint32_t i = 0; i < s1.size(); i++) {
		in_p1[i].resize(rep);
		in_p2[i].resize(rep);
		//in_p1[i] = inputs[2 * i + switchgateprogram[s1[i]]];
		//in_p2[i] = inputs[2 * i + !switchgateprogram[s1[i]]];
		outtmp = m_PM->PutCondSwapGate(inputs[2 * i], inputs[2 * i + 1], m_PM->getSwapGateAt(s1[i]));
		for (uint32_t j = 0; j < rep; j++) {
			in_p1[i][j] = outtmp[0][j];
			in_p2[i][j] = outtmp[1][j];
		}
		//cout << "Putting switchgate with selection bit: " << m_PM->getSwapGateAt(s1[i]) << " and inputs: " << in_p1[i][0] << ", and " << in_p2[i][0] << endl;
	}

	if (m_nNumInputs % 2 == 1) {
		in_p2[sizeB2 - 1].resize(rep);
		for (uint32_t i = 0; i < rep; i++)
			in_p2[sizeB2 - 1][i] = inputs[m_nNumInputs - 1][i];
	}

	vector<vector<uint32_t> > out_p1 = b1->generateCircuit(in_p1, NON_INIT_DEF_OUTPUT);
	vector<vector<uint32_t> > out_p2 = b2->generateCircuit(in_p2, NON_INIT_DEF_OUTPUT);

	// last row X
	for (uint32_t i = 0; i < s2.size(); i++) {
		//cout << "Putting switchgate with selection bit: " << m_PM->getSwapGateAt(s2[i]) << " and inputs: " << out_p1[i][0] << ", and " << out_p2[i][0] << endl;
		outtmp = m_PM->PutCondSwapGate(out_p1[i], out_p2[i], m_PM->getSwapGateAt(s2[i]));
		for (uint32_t j = 0; j < rep; j++) {
			outputs[2 * i][j] = outtmp[0][j];
			outputs[2 * i + 1][j] = outtmp[1][j];
		}
		//outputs[2 * i + switchgateprogram[s2[i]]] = out_p1[i];
		//outputs[2 * i + !switchgateprogram[s2[i]]] = out_p2[i];
	}

	for (uint32_t i = 0; i < rep; i++)
		outputs[m_nNumInputs - 1][i] = out_p2[sizeB2 - 1][i];
	if (m_nNumInputs % 2 == 0) {
		for (uint32_t i = 0; i < rep; i++)
			outputs[m_nNumInputs - 2][i] = out_p1[m_nNumInputs / 2 - 1][i];
	}

	return outputs;
}
