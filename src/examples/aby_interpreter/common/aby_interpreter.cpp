#include "aby_interpreter.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/circuit/arithmeticcircuits.h"
#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/sharing/sharing.h"

#include "build_tree.h"
#include "ezpc.h"
#include "ops.h"
#include "util.h"

#include <regex>
#include <deque>
#include <vector>
#include <stdexcept>

using namespace std::chrono;

// Constants 
const int PUBLIC = 2;
const string ARITHMETIC = "a";
const string BOOLEAN = "b";
const string YAO = "y";

// env maps all share ids to share*
std::unordered_map<std::string, std::vector<share*>>* env = new std::unordered_map<std::string, std::vector<share*>>();

// const_env maps all constant ids to constant values 
std::unordered_map<std::string, uint32_t>* const_env = new std::unordered_map<std::string, uint32_t>();

// share_type-env maps all share* to assignment
std::unordered_map<share*, std::string>* assignment_env = new std::unordered_map<share*, std::string>();

/**
 * Lazy caches store previously used share values respective to their 
 * assignments. If a wire value is reused, we can save on using additional
 * conversion gates by accessing the value from this cache.
 */ 
std::unordered_map<share*, share*>* lazy_assign_cache_a = new std::unordered_map<share*, share*>();
std::unordered_map<share*, share*>* lazy_assign_cache_b = new std::unordered_map<share*, share*>();
std::unordered_map<share*, share*>* lazy_assign_cache_y = new std::unordered_map<share*, share*>();

/** Add a (potential) conversion gate given the `from` and `to` primitives.
*
* @param from source primitive
* @param to destination primitive
* @param input_share share pointer 
* @param party ABY party
*
* @return new share pointer of the `input_share` with (potential) conversion 
* gate 
*/
share* add_conv_gate(
	std::string from, 
	std::string to, 
	share* input_share, 
	ABYParty* party) {
	std::vector<Sharing*>& sharings = party->GetSharings();
	Circuit* acirc = sharings[S_ARITH]->GetCircuitBuildRoutine();
	Circuit* bcirc = sharings[S_BOOL]->GetCircuitBuildRoutine();
	Circuit* ycirc = sharings[S_YAO]->GetCircuitBuildRoutine();

	if (from == ARITHMETIC && to == BOOLEAN) {
		// add conversion from a2b
		if (lazy_assign_cache_b->find(input_share) != lazy_assign_cache_b->end()) {
			return lazy_assign_cache_b->at(input_share);
		} else{
			share* out = bcirc->PutA2BGate(input_share, ycirc);
			(*lazy_assign_cache_b)[input_share] = out;
			return out;
		}
	} else if (from == ARITHMETIC && to == YAO) {
		// add conversion from a2y
		if (lazy_assign_cache_y->find(input_share) != lazy_assign_cache_y->end()) {
			return lazy_assign_cache_y->at(input_share);
		} else{
			share* out = ycirc->PutA2YGate(input_share);
			(*lazy_assign_cache_y)[input_share] = out;
			return out;
		}
	} else if (from == BOOLEAN && to == ARITHMETIC) {
		// add conversion from b2a
		if (lazy_assign_cache_a->find(input_share) != lazy_assign_cache_a->end()) {
			return lazy_assign_cache_a->at(input_share);
		} else{
			share* out = acirc->PutB2AGate(input_share);
			(*lazy_assign_cache_a)[input_share] = out;
			return out;
		}
	}  else if (from == BOOLEAN && to == YAO) {
		// add conversion from b2y
		if (lazy_assign_cache_y->find(input_share) != lazy_assign_cache_y->end()) {
			return lazy_assign_cache_y->at(input_share);
		} else{
			share* out = ycirc->PutB2YGate(input_share);
			(*lazy_assign_cache_y)[input_share] = out;
			return out;
		}
	} else if (from == YAO && to == ARITHMETIC) {
		// add conversion from y2a
		if (lazy_assign_cache_a->find(input_share) != lazy_assign_cache_a->end()) {
			return lazy_assign_cache_a->at(input_share);
		} else{
			share* out = acirc->PutY2AGate(input_share, bcirc);
			(*lazy_assign_cache_a)[input_share] = out;
			return out;
		}
	} else if (from == YAO && to == BOOLEAN) {
		// add conversion from y2b
		if (lazy_assign_cache_b->find(input_share) != lazy_assign_cache_b->end()) {
			return lazy_assign_cache_b->at(input_share);
		} else{
			share* out =  bcirc->PutY2BGate(input_share);
			(*lazy_assign_cache_b)[input_share] = out;
			return out;
		}
	} else {
		// no conversion is necessary
		return input_share;
	}
}

/** Get `Circuit` for a given circuit_type
*
* @param circuit_type string of circuit_type
* @param party ABY party
*
* @return Circuit* used to construct circuits of a particular primitive 
*
*/
Circuit* get_circuit(std::string circuit_type, ABYParty* party) {
	std::vector<Sharing*>& sharings = party->GetSharings();
	if (circuit_type == ARITHMETIC) {
		return sharings[S_ARITH]->GetCircuitBuildRoutine();
	} else if (circuit_type == BOOLEAN) {
		return sharings[S_BOOL]->GetCircuitBuildRoutine();
	} else if (circuit_type == YAO) {
		return sharings[S_YAO]->GetCircuitBuildRoutine();
	} else {
		throw std::invalid_argument("Unknown circuit type: " + circuit_type);
	}
}

/** Process a single instruction (statement) from bytecode
*
* @param circuit_type string of circuit_type
* @param rewire_inputs deque of shares to rewire arguments to functions 
* @param rewire_outputs deque of strings to rewire return values from functions 
* @param params test arguments 
* @param input_wires names (vec<string>) of input wires
* @param output_wires names (vec<string>) of output wires
* @param out vector of output shares 
* @param op operator 
* @param role server or client 
* @param bitlen circuit bitlen
* @param party ABY party
*
*/
void process_instruction(
	std::string circuit_type,
	std::deque<share*>* rewire_inputs,
	std::deque<string>* rewire_outputs,
	std::unordered_map<std::string, uint32_t>* params,
	std::vector<std::string> input_wires, 
	std::vector<std::string> output_wires, 
	std::vector<share*>* out, 
	std::string op,
	e_role role, 
	uint32_t bitlen,
	ABYParty* party) {

	// get circuit builders
	std::vector<Sharing*>& sharings = party->GetSharings();
	Circuit* acirc = sharings[S_ARITH]->GetCircuitBuildRoutine();
	Circuit* bcirc = sharings[S_BOOL]->GetCircuitBuildRoutine();
	Circuit* ycirc = sharings[S_YAO]->GetCircuitBuildRoutine();

	// end result of op
	share* result;

	
	if (is_bin_op(op_hash(op))) {	
		Circuit* circ = get_circuit(circuit_type, party);	

		// get binary operands
		share* wire1 = env->at(input_wires[0])[0];
		share* wire2 = env->at(input_wires[1])[0];
		std::string share_type_1 = assignment_env->at(wire1);
		std::string share_type_2 = assignment_env->at(wire2);
		wire1 = add_conv_gate(share_type_1, circuit_type, wire1, party);
		wire2 = add_conv_gate(share_type_2, circuit_type, wire2, party);

		switch(op_hash(op)) {
			case ADD_: {
				result = circ->PutADDGate(wire1, wire2);
				break;
			}
			case SUB_: {
				result = circ->PutSUBGate(wire1, wire2);
				break;
			}
			case MUL_: {
				// const mult trick
				if (circuit_type == YAO || circuit_type == BOOLEAN) {
					if(const_env->find(input_wires[0]) != const_env->end()) {
						uint32_t value = const_env->at(input_wires[0]);
						result = const_mult(circ, wire2, value);
					} else if (const_env->find(input_wires[1]) != const_env->end()) {
						uint32_t value = const_env->at(input_wires[1]);
						result = const_mult(circ, wire1, value);
					} else {
						result = circ->PutMULGate(wire1, wire2);
					}
				} else{
					result = circ->PutMULGate(wire1, wire2);
				}
				break;
			}
			case GT_: {
				result = circ->PutGTGate(wire1, wire2);
				break;
			}
			case LT_: {
				result = circ->PutGTGate(wire2, wire1);
				break;
			}
			case GE_: {
				result = ((BooleanCircuit *)circ)->PutINVGate(circ->PutGTGate(wire2, wire1));
				break;
			}
			case LE_: {
				result = ((BooleanCircuit *)circ)->PutINVGate(circ->PutGTGate(wire1, wire2));
				break;
			}
			case REM_: {
				result = signedmodbl(circ, wire1, wire2);
				break;
			}
			case AND_: {
				result = circ->PutANDGate(wire1, wire2);
				break;
			}
			case OR_: {
				result = ((BooleanCircuit *)circ)->PutORGate(wire1, wire2);
				break;
			}
			case XOR_: {
				result = circ->PutXORGate(wire1, wire2);
				break;
			}
			case DIV_: {
				result = signeddivbl(circ, wire1, wire2);
				break;
			} 
			case EQ_: {
				result = circ->PutEQGate(wire1, wire2);
				break;
			}
			default: {
				throw std::invalid_argument("Unknown binop: " + op);
			}
		}
		for (auto o: output_wires) {
			(*env)[o] = {result};
			(*assignment_env)[result] = circuit_type;
		}
	} else {
		switch(op_hash(op)) {
			case CONS_: {
				// ABY requires all boolean inputs to be generated from bcirc
				if (circuit_type == YAO) {
					circuit_type = BOOLEAN;
				}
				int value = std::stoi(input_wires[0]);
				int len = std::stoi(input_wires[1]);
				if (circuit_type == ARITHMETIC) {
					if (len == 1) {
						result = put_cons1_gate(acirc, value);
					} else if (len == 32) {
						result = put_cons32_gate(acirc, value);
					} else {
						throw std::runtime_error("Unknown const bit len: "+input_wires[2]);
					}
				} else if (circuit_type == BOOLEAN) {
					if (len == 1) {
						result = put_cons1_gate(bcirc, value);
					} else if (len == 32) {
						result = put_cons32_gate(bcirc, value);
					} else {
						throw std::runtime_error("Unknown const bit len: "+input_wires[2]);
					}
				} else {
					throw std::runtime_error("Unknown share type: "+circuit_type);
				}
				for (auto o: output_wires) {
					(*env)[o] = {result};
					(*assignment_env)[result] = circuit_type;
				}
				break;
			}
			case MUX_: {
				assert(("input_wires len is odd", input_wires.size() % 2 == 1));
				Circuit* circ = get_circuit(circuit_type, party);
				
				// get conditional 
				share* sel = env->at(input_wires[0])[0];
				std::string share_type_sel = assignment_env->at(sel);
				sel = add_conv_gate(share_type_sel, circuit_type, sel, party);

				auto len = (input_wires.size() - 1) / 2;

				// true wires
				auto start = 1;
				std::vector<std::string> t_strs(len);
				std::copy(input_wires.begin() + start, input_wires.begin() + len + start, t_strs.begin()); 

				// false wires
				start += len;
				std::vector<std::string> f_strs(len);
				std::copy(input_wires.begin() + start, input_wires.begin() + len + start, f_strs.begin()); 

				for (int i = 0; i < len; i++) {
					auto t_wire = env->at(t_strs[i])[0];
					auto f_wire = env->at(f_strs[i])[0];

					if (t_wire == f_wire){
						result = t_wire;
						(*assignment_env)[result] = assignment_env->at(result);
					} else{
						std::string t_share_type = assignment_env->at(t_wire);
						std::string f_share_type = assignment_env->at(f_wire);
						t_wire = add_conv_gate(t_share_type, circuit_type, t_wire, party);
						f_wire = add_conv_gate(f_share_type, circuit_type, f_wire, party);

						result = circ->PutMUXGate(t_wire, f_wire, sel);
						(*assignment_env)[result] = circuit_type;
					}
					(*env)[output_wires[i]] = {result};
				}
				break;
			}
			case NOT_: {
				Circuit* circ = get_circuit(circuit_type, party);
				share* wire = env->at(input_wires[0])[0];
				std::string share_type = assignment_env->at(wire);
				wire = add_conv_gate(share_type, circuit_type, wire, party);
				result = ((BooleanCircuit *)circ)->PutINVGate(wire);
				(*assignment_env)[result] = circuit_type;
				for (auto o: output_wires) {
					(*env)[o] = {result};
				}
				break;
			}
			case SHL_: {
				Circuit* circ = get_circuit(circuit_type, party);
				share* wire = env->at(input_wires[0])[0];
				auto share_type_from = assignment_env->at(wire);
				wire = add_conv_gate(share_type_from, circuit_type, wire, party);
				int value = std::stoi(input_wires[1]);
				result = left_shift(circ, wire, value);
				(*assignment_env)[result] = circuit_type;
				for (auto o: output_wires) {
					(*env)[o] = {result};
				}
				break;
			} 
			case LSHR_: {
				Circuit* circ = get_circuit(circuit_type, party);
				share* wire = env->at(input_wires[0])[0];
				auto share_type_from = assignment_env->at(wire);
				wire = add_conv_gate(share_type_from, circuit_type, wire, party);
				int value = std::stoi(input_wires[1]);
				result = logical_right_shift(circ, wire, value);
				(*assignment_env)[result] = circuit_type;
				for (auto o: output_wires) {
					(*env)[o] = {result};
				}
				break;
			} 
			case SELECT_: {
				assert(("Select circuit type not supported in arithmetic sharing", circuit_type != ARITHMETIC));
				Circuit* circ = get_circuit(circuit_type, party);

				// get index wire
				auto index = input_wires[input_wires.size()-1];
				auto index_wire = env->at(index)[0];
				index_wire = add_conv_gate(assignment_env->at(index_wire), circuit_type, index_wire, party);

				// Rather than linear pairwise comparisons in the target vector,
				// we can get amoritized savings by transforming this linear 
				// scan into a log-tree structure.
                std::vector<std::vector<share*>> columns;
                for (int i = 0; i < 32; i++) {
                    std::vector<share*> cols;
                    columns.push_back(cols);
                }
				
				// initialize input values
                for (int i = 0; i < input_wires.size()-1; i++) {
                    share* wire = env->at(input_wires[i])[0];
					wire = add_conv_gate(assignment_env->at(wire), circuit_type, wire, party);
                    for (int w = 0; w < wire->get_bitlength(); w++) {
                        columns[w].push_back(wire->get_wire_ids_as_share(w));
                    }
                }

				// tree based comparisons 
                std::vector<uint32_t> outputs;
                for (int i = 0; i < columns.size(); i++) {
                    auto inputs = columns[i];
                    share* selected = build_tree(inputs, [&](share* a, share* b, int level) {
                        share* level_wire = index_wire->get_wire_ids_as_share(level);
                        return circ->PutXORGate(a, circ->PutANDGate(level_wire, circ->PutXORGate(a,b)));
                    });
                    outputs.push_back(selected->get_wire_id(0));
                }

				// store results
                share* res = new boolshare(outputs.size(), circ);
                res->set_wire_ids(outputs);

				assert(("more than one output wire", output_wires.size() == 1));
				(*env)[output_wires[0]] = {res};
				(*assignment_env)[res] = circuit_type;
				break;
			}
			case STORE_: {
				assert(("Store circuit type not supported in arithmetic sharing", circuit_type != ARITHMETIC));
				assert(("len of input wires == len output wires + 2", input_wires.size() == output_wires.size() + 2));
				Circuit* circ = get_circuit(circuit_type, party);

				// get value share
				auto value = input_wires[input_wires.size()-1];
				auto value_wire = env->at(value)[0];
				value_wire = add_conv_gate(assignment_env->at(value_wire), circuit_type, value_wire, party);
				
				// get index share 
				auto index = input_wires[input_wires.size()-2];
				auto index_wire = env->at(index)[0];
				index_wire = add_conv_gate(assignment_env->at(index_wire), circuit_type, index_wire, party);

				for (int i = 0; i < output_wires.size(); i++) {
					share* ind = put_cons32_gate(bcirc, i);
					ind = add_conv_gate(BOOLEAN, circuit_type, ind, party);
					share* sel = circ->PutEQGate(ind, index_wire);
					auto array_wire = env->at(input_wires[i])[0];
					array_wire = add_conv_gate(assignment_env->at(array_wire), circuit_type, array_wire, party);
					result = circ->PutMUXGate(value_wire, array_wire, sel);
					(*env)[output_wires[i]] = {result};
					(*assignment_env)[result] = circuit_type;
 				}
				break;
			}
			case IN_: {
				// rewire arguments into function call 
				if (rewire_inputs->size() > 0) {
					share* rewire_share = rewire_inputs->front();
					std::string share_type_from = assignment_env->at(rewire_share);
					(*env)[output_wires[0]] = {rewire_share};
					rewire_inputs->pop_front();
					break;
				} else {
					// ABY requires all boolean inputs to be generated from bcirc
					if (circuit_type == YAO) {
						circuit_type = BOOLEAN;
					}
					Circuit* circ = get_circuit(circuit_type, party);
					std::string var_name = input_wires[0];
					uint32_t value = params->at(var_name);
					int vis = std::stoi(input_wires[1]);
					if (vis == (int) role) {
						result = circ->PutINGate(value, bitlen, role);
					} else if (vis == PUBLIC) {
						int len = std::stoi(input_wires[2]);
						if (len == 1) {
							result = put_cons1_gate(circ, value);
						} else {
							result = put_cons32_gate(circ, value);
						}
					} else {
						result = circ->PutDummyINGate(bitlen);
					} 
					(*assignment_env)[result] = circuit_type;
				}
				for (auto o: output_wires) {
					(*env)[o] = {result};
				}
				break;
			}
			case OUT_: {
				// rewire retursn from function call
				if (rewire_outputs->size() > 0) {
					std::vector<share*> wires = env->at(input_wires[0]);
					for (auto wire: wires) {
						std::string output_str = rewire_outputs->front();
						(*env)[output_str] = {wire};	
						rewire_outputs->pop_front();
					}	
				} else {
					std::vector<share*> wires = env->at(input_wires[0]);
					for (auto wire: wires) {
						std::string share_type_from = assignment_env->at(wire);
						Circuit* circ = get_circuit(share_type_from, party);
						result = circ->PutOUTGate(wire, ALL);		
						out->push_back(result);			
					}				
				}
				break;
			}
			default: {
				throw std::invalid_argument("Unknown op: " + op);
			}
		}
	}
	
}

/** Process bytecode file
*
* @param fn function name
* @param bytecode_paths map of bytecode file paths
* @param rewire_inputs deque of shares to rewire arguments to functions 
* @param rewire_outputs deque of strings to rewire return values from functions 
* @param params test arguments 
* @param share_map map of assignment decisions for each wire id
* @param role server or client 
* @param bitlen circuit bitlen
* @param party ABY party
*
* @return return share* from bytecode 
*
*/
std::vector<share*> process_bytecode(
	std::string fn, 
	std::unordered_map<std::string, std::string>* bytecode_paths,
	std::deque<share*> rewire_inputs,
	std::deque<std::string> rewire_outputs,
	std::unordered_map<std::string, uint32_t>* params,
	std::unordered_map<std::string, std::string>* share_map,
	e_role role,
	uint32_t bitlen,
	ABYParty* party) {
	// std::cout << "LOG: processing function: " << fn << std::endl;
	auto path = bytecode_paths->at(fn);
	std::ifstream file(path);
	assert(("Bytecode file exists.", file.is_open()));
	if (!file.is_open()) throw std::runtime_error("Bytecode file doesn't exist -- "+path);
	
	std::vector<share*> out;
	std::string str;
	while (std::getline(file, str)) {
        std::vector<std::string> line = split_(str);
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
			// set circuit_type if function returns value 
			circuit_type = share_map->at(output_wires[0]);
		} else {
			if (share_map->find(input_wires[0]) != share_map->end()) {
				// set circuit_type to first input_wire
				circuit_type = share_map->at(input_wires[0]);
			} else {
				// this case is reached if the input is not used at all in the computation.
				if (op_hash(op) == IN_) {
					// if skipping an IN operation, remove a rewire
					if (rewire_inputs.size() > 0)
						rewire_inputs.pop_front();
				}
				continue;
			}
		}

		if (is_call_op(op)) { // process function and handle rewiring
			// input and output wires are concatenated into a vector and then used for 
			// rewiring the input and output wires of the function
			std::deque<share*> rewire_inputs;
			std::deque<std::string> rewire_outputs;
			for (auto i: input_wires) {
				auto wires = env->at(i);
				rewire_inputs.insert(rewire_inputs.end(), wires.begin(), wires.end());
			}
			rewire_outputs.insert(rewire_outputs.end(), output_wires.begin(), output_wires.end());
			
			// recursively call process bytecode on function body
			auto fn =  parse_fn_name(op);
			std::vector<share*> out_shares = process_bytecode(fn, bytecode_paths, rewire_inputs, rewire_outputs, params, share_map, role, bitlen, party);	

			assert(("Out_shares and output_wires are the same size", out_shares.size() == output_wires.size()));
			for (int i = 0; i < out_shares.size(); i++) {
				(*env)[output_wires[i]] = {out_shares[i]};
			}
		} else { // process single instruction
			process_instruction(circuit_type, &rewire_inputs, &rewire_outputs, params, input_wires, output_wires, &out, op, role, bitlen, party);
			assert(("Len of output_wires should be at most 1", output_wires.size() <= 1));
		}
	}
	return out;
}

/** Process const file
*
* @param const_path path to constants
* @param share_map map of assignment decisions for each wire id
* @param role server or client 
* @param bitlen circuit bitlen
* @param party ABY party
*
*/
void process_const(
	std::string const_path, 
	std::unordered_map<std::string, std::string>* share_map,
	e_role role,
	uint32_t bitlen,
	ABYParty* party){
	std::ifstream file(const_path);
	if (!file.is_open()) {
		return;
	}

	std::vector<share*> out;
	std::string str;
	while (std::getline(file, str)) {
        std::vector<std::string> line = split_(str);
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
			circuit_type = share_map->at(output_wires[0]);
		} else {
			circuit_type = share_map->at(input_wires[0]);
		}

		process_instruction(circuit_type, {}, {}, {}, input_wires, output_wires, &out, op, role, bitlen, party);
		assert(("Len of output_wires should be at most 1", output_wires.size() <= 1));
	}
}

/** Interpret circuit 
*
* @param bytecode_paths map of bytecode file paths
* @param const_path path to constants
* @param params test arguments 
* @param share_map map of assignment decisions for each wire id
* @param role server or client
* @param address address to connect to
* @param port port to connect to
* @param seclvl seclvl
* @param bitlen circuit bitlen
* @param nthreads nthreads
* @param e_mt_gen_alg mt_alg
* @param e_sharing sharing
*
* @return execution time  
*
*/
double interpret_circuit(
	std::unordered_map<std::string, std::string>* bytecode_paths, 
	std::string const_path,
	std::unordered_map<std::string, uint32_t>* params, 
	std::unordered_map<std::string, std::string>* share_map,
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
	output_queue out_q;

	// process consts 
	process_const(const_path, share_map, role, bitlen, party);

	// process bytecode
	vector<share*> out_shares = process_bytecode("main", bytecode_paths, {}, {}, params, share_map, role, bitlen, party);	

	// multiple outputs
	for (auto s: out_shares) {
		add_to_output_queue(out_q, s, role, std::cout);
	}
	
	// add timing code
	high_resolution_clock::time_point start_exec_time = high_resolution_clock::now();
	party->ExecCircuit();
	high_resolution_clock::time_point end_exec_time = high_resolution_clock::now();
	duration<double> exec_time = duration_cast<duration<double>>(end_exec_time - start_exec_time);

	std::cout << "LOG: " << (role == SERVER ? "Server exec time: " : "Client exec time: ") << exec_time.count() << std::endl;

	// print result of computation
	flush_output_queue(out_q, role, bitlen);
	
	delete env;
	delete const_env;
	delete assignment_env;
	delete lazy_assign_cache_a;
	delete lazy_assign_cache_b;
	delete lazy_assign_cache_y;
	delete party;
	return exec_time.count();
}