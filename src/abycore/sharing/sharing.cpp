/**
 \file 		sharing.cpp
 \author	michael.zohner@ec-spride.de
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
 \brief		Sharing class implementation.
 */
#include "sharing.h"

void Sharing::EvaluateCallbackGate(uint32_t gateid) {
	GATE* gate = m_pGates + gateid;
	void (*callback)(GATE*, void*) = gate->gs.cbgate.callback;
	void* infos = gate->gs.cbgate.infos;
	InstantiateGate(gate);

	callback(gate, infos);

	for(uint32_t i = 0; i < gate->ingates.ningates; i++)
		UsedGate(gate->ingates.inputs.parents[i]);
	free(gate->ingates.inputs.parents);
}

//TODO switch on gate and perform SIMD gate routine

