#include "aby_interpreter.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/circuit/arithmeticcircuits.h"
#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/sharing/sharing.h"
#include "../../../../../../EZPC/ezpc.h"

enum op {
	ADD
};

op op_hash(std::string op) {
    if (op == "ADD") return ADD;
    throw std::invalid_argument("Unknown mode: "+op);
}

std::vector<std::string> split(std::string str, char delimiter) {
    std::vector<std::string> result;
    std::istringstream ss(str);
    std::string word; 
    while (ss >> word) {
        result.push_back(word);
    }
    return result;
}

share* get_from_cache(std::unordered_map<std::string, share*> cache, std::string key) {
	std::unordered_map<std::string, share*>::const_iterator wire = cache.find(key);
	if (wire == cache.end()){
		throw std::invalid_argument("Unknown wire: " + key);
	}
	else {
		return wire->second;
	}
}

std::string get_from_params(std::unordered_map<std::string, std::string> params, std::string key) {
	std::unordered_map<std::string, std::string>::const_iterator p = params.find(key);
	if (p == params.end()){
		throw std::invalid_argument("Unknown wire: " + key);
	}
	else {
		return p->second;
	}
}

Circuit* get_circuit(Circuit* acirc, Circuit* bcirc, Circuit* ycirc, std::string circuit_type) {
	Circuit* circ;
	if (circuit_type == "a") {
		circ = acirc;
	} else if (circuit_type == "b") {
		circ = bcirc;
	} else if (circuit_type == "y") {
		circ = ycirc;
	} else {
		throw std::invalid_argument("Unknown circuit type: " + circuit_type);
	}
	return circ;
}

share* process_instruction(Circuit* circ, std::unordered_map<std::string, share*> cache, 
	std::vector<std::string> input_wires, std::vector<std::string> output_wires, std::string op) {
	share* result;
	share* wire1 = get_from_cache(cache, input_wires[0]);
	share* wire2 = get_from_cache(cache, input_wires[1]);
	switch(op_hash(op)) {
		case ADD: {
			result = circ->PutADDGate(wire1, wire2);
		}
	}
	return result;
}

void process_bytecode(std::string bytecode_file_path, 
	std::unordered_map<std::string, share*> cache,
	Circuit* acirc, Circuit* bcirc, Circuit* ycirc) {
	std::ifstream file(bytecode_file_path);
    assert(("Test file exists.", file.is_open()));

	std::string str;
	while (std::getline(file, str)) {
        std::vector<std::string> line = split(str, ' ');
		if (line.size() < 4) continue;
		int num_inputs = std::stoi(line[0]);
		int num_outputs = std::stoi(line[1]);
		std::vector<std::string> input_wires = std::vector<std::string>(num_inputs);
		std::vector<std::string> output_wires = std::vector<std::string>(num_outputs);
		for (int i = 0; i < num_inputs; i++) {
			input_wires[i] = line[2+i];
		}
		for (int i = 0; i < num_outputs; i++) {
			output_wires[i] = line[2+num_inputs+i];
		}
		std::string op = line[2+num_inputs+num_outputs];
		std::string circuit_type = line[2+num_inputs+num_outputs+1];
		Circuit* circ = get_circuit(acirc, bcirc, ycirc, circuit_type);
		share* output = process_instruction(circ, cache, input_wires, output_wires, op);
		for (auto o: output_wires) {
			cache[o] = output;
		}
	}
}

std::unordered_map<std::string, share*> process_input_params(
	std::string params_file_path, 
	std::unordered_map<std::string, int> params,
	Circuit* acirc, Circuit* bcirc, Circuit* ycirc) {
	std::ifstream file(params_file_path);
    assert(("Test file exists.", file.is_open()));
	int count = 0;
	std::string str;
	while (std::getline(file, str)) {
		std::vector<std::string> line = split(str, ' ');
		
		// Add share to map
		std::string wire_name = line[0];
		std::string share_str = line[1];
		std::string circuit_type = line[2];
		Circuit* circ = get_circuit(acirc, bcirc, ycirc, circuit_type);
		
		// get value from wire name 
		// PutInGate 
		// add share to cache 
	}
}


int32_t test_aby_test_circuit(
	std::string bytecode_file_path, 
	std::unordered_map<std::string, int> params, 
	e_role role, 
	const std::string& address, 
	uint16_t port, 
	seclvl seclvl, 
	uint32_t bitlen,
	uint32_t nthreads, 
	e_mt_gen_alg mt_alg, 
	e_sharing sharing) {

	// setup
	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
	std::vector<Sharing*>& sharings = party->GetSharings();
	Circuit* acirc = sharings[S_ARITH]->GetCircuitBuildRoutine();
	Circuit* bcirc = sharings[S_BOOL]->GetCircuitBuildRoutine();
	Circuit* ycirc = sharings[S_YAO]->GetCircuitBuildRoutine();
	output_queue out_q;

	party->ExecCircuit();
	flush_output_queue(out_q, role, bitlen);
	delete party;
	return 0;
}
