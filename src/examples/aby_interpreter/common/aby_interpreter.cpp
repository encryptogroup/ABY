#include "aby_interpreter.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/circuit/arithmeticcircuits.h"
#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/sharing/sharing.h"
#include "ezpc.h"

enum op {
	ADD_,
	SUB_,
	MUL_,
	EQ_bv,
	EQ_bool,
	GT_,
	LT_,
	GE_,
	LE_,
	REM_,
	AND_,
	OR_,
	XOR_,
	CONS_bv,
	CONS_bool,
	MUX_, 
	NOT_,
	DIV_,
	OUT_,
};

op op_hash(std::string o) {
    if (o == "ADD") return ADD_;
	if (o == "SUB") return SUB_;
	if (o == "MUL") return MUL_;
	if (o == "EQ_bv") return EQ_bv;
	if (o == "EQ_bool") return EQ_bool;
	if (o == "GT") return GT_;
	if (o == "LT") return LT_;
	if (o == "GE") return GE_;
	if (o == "LE") return LE_;
	if (o == "REM") return REM_;
	if (o == "AND") return AND_;
	if (o == "OR") return OR_;
	if (o == "XOR") return XOR_;
	if (o == "CONS_bv") return CONS_bv;
	if (o == "CONS_bool") return CONS_bool;
	if (o == "MUX") return MUX_;
	if (o == "NOT") return NOT_;
	if (o == "DIV") return DIV_;
	if (o == "OUT") return OUT_;
    throw std::invalid_argument("Unknown operator: "+o);
}

std::vector<std::string> split_(std::string str, char delimiter) {
    std::vector<std::string> result;
    std::istringstream ss(str);
    std::string word; 
    while (ss >> word) {
        result.push_back(word);
    }
    return result;
}

share* get_from_cache(std::unordered_map<std::string, share*>* cache, std::string key) {	
	std::unordered_map<std::string, share*>::const_iterator wire = cache->find(key);
	if (wire == cache->end()){
		throw std::invalid_argument("Unknown wire in cache: " + key);
	}
	else {
		return wire->second;
	}
}

std::string get(std::unordered_map<std::string, std::string>* map, std::string key) {
	std::unordered_map<std::string, std::string>::const_iterator m = map->find(key);
	if (m == map->end()){
		throw std::invalid_argument("Unknown wire: " + key);
	}
	else {
		return m->second;
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

share* process_instruction(
	Circuit* circ, 
	std::unordered_map<std::string, share*>* cache, 
	std::vector<std::string> input_wires, 
	std::vector<std::string> output_wires, 
	std::string op) {
	
	share* result;
	switch(op_hash(op)) {
		case ADD_: {
			share* wire1 = get_from_cache(cache, input_wires[0]);
			share* wire2 = get_from_cache(cache, input_wires[1]);
			result = circ->PutADDGate(wire1, wire2);
			break;
		}
		case SUB_: {
			share* wire1 = get_from_cache(cache, input_wires[0]);
			share* wire2 = get_from_cache(cache, input_wires[1]);
			result = circ->PutSUBGate(wire1, wire2);
			break;
		}
		case MUL_: {
			share* wire1 = get_from_cache(cache, input_wires[0]);
			share* wire2 = get_from_cache(cache, input_wires[1]);
			result = circ->PutMULGate(wire1, wire2);
			break;
		}
		case EQ_bv: {
			share* wire1 = get_from_cache(cache, input_wires[0]);
			share* wire2 = get_from_cache(cache, input_wires[1]);
			share* one = put_cons32_gate(circ, 1);
			result = circ->PutXORGate(circ->PutXORGate(circ->PutGTGate(wire1, wire2), circ->PutGTGate(wire2, wire1)), one);
			break;
		}
		case EQ_bool: {
			share* wire1 = get_from_cache(cache, input_wires[0]);
			share* wire2 = get_from_cache(cache, input_wires[1]);
			share* one = put_cons1_gate(circ, 1);
			result = circ->PutXORGate(circ->PutXORGate(wire1, wire2), one);
			break;
		}
		case GT_: {
			share* wire1 = get_from_cache(cache, input_wires[0]);
			share* wire2 = get_from_cache(cache, input_wires[1]);
			result = circ->PutGTGate(wire1, wire2);
			break;
		}
		case LT_: {
			share* wire1 = get_from_cache(cache, input_wires[0]);
			share* wire2 = get_from_cache(cache, input_wires[1]);
			result = circ->PutGTGate(wire2, wire1);
			break;
		}
		case GE_: {
			share* wire1 = get_from_cache(cache, input_wires[0]);
			share* wire2 = get_from_cache(cache, input_wires[1]);
			result = ((BooleanCircuit *)circ)->PutINVGate(circ->PutGTGate(wire2, wire1));
			break;
		}
		case LE_: {
			share* wire1 = get_from_cache(cache, input_wires[0]);
			share* wire2 = get_from_cache(cache, input_wires[1]);
			result = ((BooleanCircuit *)circ)->PutINVGate(circ->PutGTGate(wire1, wire2));
			break;
		}
		case REM_: {
			share* wire1 = get_from_cache(cache, input_wires[0]);
			share* wire2 = get_from_cache(cache, input_wires[1]);
			result = signedmodbl(circ, wire1, wire2);
			break;
		}
		case AND_: {
			share* wire1 = get_from_cache(cache, input_wires[0]);
			share* wire2 = get_from_cache(cache, input_wires[1]);
			result = circ->PutANDGate(wire1, wire2);
			break;
		}
		case OR_: {
			share* wire1 = get_from_cache(cache, input_wires[0]);
			share* wire2 = get_from_cache(cache, input_wires[1]);
			result = ((BooleanCircuit *)circ)->PutORGate(wire1, wire2);
			break;
		}
		case XOR_: {
			share* wire1 = get_from_cache(cache, input_wires[0]);
			share* wire2 = get_from_cache(cache, input_wires[1]);
			result = circ->PutXORGate(wire1, wire2);
			break;
		}
		case CONS_bv: {
			int value = std::stoi(input_wires[0]);
			result = put_cons64_gate(circ, value);
			break;
		}
		case CONS_bool: {
			int value = std::stoi(input_wires[0]);
			result = put_cons1_gate(circ, value);
			break;
		}
		case MUX_: {
			share* sel = get_from_cache(cache, input_wires[0]);
			share* wire1 = get_from_cache(cache, input_wires[1]);
			share* wire2 = get_from_cache(cache, input_wires[2]);
			result = circ->PutMUXGate(wire1, wire2, sel);
			break;
		}
		case NOT_: {
			share* wire = get_from_cache(cache, input_wires[0]);
			result = ((BooleanCircuit *)circ)->PutINVGate(wire);
			break;
		}
		case DIV_: {
			share* wire1 = get_from_cache(cache, input_wires[0]);
			share* wire2 = get_from_cache(cache, input_wires[1]);
			result = signeddivbl(circ, wire1, wire2);
			break;
		}
		case OUT_: {
			share* wire = get_from_cache(cache, input_wires[0]);
 			result = circ->PutOUTGate(wire, ALL);
			break;
		}
	}
	return result;
}

share* process_bytecode(
	std::string bytecode_path,
	std::unordered_map<std::string, share*>* cache,
	std::unordered_map<std::string, std::string>* mapping,
	Circuit* acirc, 
	Circuit* bcirc, 
	Circuit* ycirc) {
	std::ifstream file(bytecode_path);
	assert(("Bytecode file exists.", file.is_open()));
	if (!file.is_open()) throw std::runtime_error("Bytecode file doesn't exist -- "+bytecode_path);
	std::string str;
	share* last_instr;
	Circuit* circ;
	while (std::getline(file, str)) {
        std::vector<std::string> line = split_(str, ' ');

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
		std::string circuit_type;

		if (num_outputs) {
			circuit_type = get(mapping, output_wires[0]);
		} else {
			circuit_type = get(mapping, input_wires[0]);
		}
		
		circ = get_circuit(acirc, bcirc, ycirc, circuit_type);
		last_instr = process_instruction(circ, cache, input_wires, output_wires, op);
		for (auto o: output_wires) {
			(*cache)[o] = last_instr;
		}
	}
	if (last_instr == NULL) throw std::runtime_error("Return value is null.");
	return last_instr;
}

void process_input_params(
	std::unordered_map<std::string, share*>* cache,
	std::unordered_map<std::string, std::tuple<std::string, uint32_t, uint32_t>>* params,
	std::unordered_map<std::string, std::string>* mapping,
	e_role role,
	uint32_t bitlen,
	Circuit* acirc, 
	Circuit* bcirc, 
	Circuit* ycirc) {
	std::string role_str = (role == 0) ? "server" : "client";
	for (auto p: *params) {
		std::string param_name = p.first;
		std::string param_role = std::get<0>(p.second);
		uint32_t param_value = std::get<1>(p.second);
		uint32_t param_index = std::get<2>(p.second);
		if (param_index == (uint32_t)-1) continue;		
		std::string circuit_type = get(mapping, std::to_string(param_index));
		Circuit* circ = get_circuit(acirc, bcirc, ycirc, circuit_type);
		share* param_share;
		if (param_role == role_str) {
			param_share = circ->PutINGate(param_value, bitlen, role);
		} else {
			param_share = circ->PutDummyINGate(bitlen);
		}
		(*cache)[std::to_string(param_index)] = param_share;
	}
}


int32_t test_aby_test_circuit(
	std::string bytecode_path, 
	std::unordered_map<std::string, std::tuple<std::string, uint32_t, uint32_t>>* params, 
	std::unordered_map<std::string, std::string>* mapping,
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

	// share cache
	std::unordered_map<std::string, share*>* cache = new std::unordered_map<std::string, share*>();

	// process input params
	process_input_params(cache, params, mapping, role, bitlen, acirc, bcirc, ycirc);

	// process bytecode
	share* out_share = process_bytecode(bytecode_path, cache, mapping, acirc, bcirc, ycirc);

	add_to_output_queue(out_q, out_share, role, std::cout);
	party->ExecCircuit();
	flush_output_queue(out_q, role, bitlen);
	delete cache;
	delete party;
	return 0;
}
