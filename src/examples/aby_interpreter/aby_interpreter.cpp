#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
#include "../../abycore/aby/abyparty.h"
#include "common/aby_interpreter.h"

#include "argparse.hpp"

enum mode {
    mpc
};

mode hash_mode(std::string m) {
    if (m == "mpc") return mpc;
    throw std::invalid_argument("Unknown mode: "+m);
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

uint32_t get_from_param_map(std::unordered_map<std::string, uint32_t>* map, std::string key) {
    std::unordered_map<std::string, uint32_t>::const_iterator m = map->find(key);
	if (m == map->end()){
        // if the parameter isn't used
		return -1;
	}
	else {
		return m->second;
	}
}


std::unordered_map<std::string, std::tuple<std::string, uint32_t, uint32_t>> parse_mpc_inputs(std::string test_path, std::string param_map_path) {
    std::ifstream param_file(param_map_path);
    assert(("Param map file exists.", param_file.is_open()));
    if (!param_file.is_open()) throw std::runtime_error("Param map file doesn't exist. -- " + param_map_path);
    
    std::unordered_map<std::string, uint32_t> param_map;
    std::string str;
    while (std::getline(param_file, str)) {
        std::vector<std::string> line = split(str, ' ');
        if (line.size() == 0) continue;
        if (line.size() == 2) {
            param_map[line[0]] = (uint32_t)std::stoi(line[1]);
        }
    }

    std::ifstream file(test_path);
    assert(("Test file exists.", file.is_open()));
    if (!file.is_open()) throw std::runtime_error("Test file doesn't exist.");
    
    std::unordered_map<std::string, std::tuple<std::string, uint32_t, uint32_t>> input_map;
    bool server_flag = false;
    bool client_flag = false;
    uint32_t num_params = 0;
    while (std::getline(file, str)) {
        std::vector<std::string> line = split(str, ' ');
        if (line.size() == 0) continue;
        if (line[0].rfind("//", 0) == 0) {
            server_flag = false;
            client_flag = false;
        }
        if (line[0].rfind("//", 0) == 0 && line[1] == "server") {
            server_flag = true;
            client_flag = false;
            continue;
        }
        if (line[0].rfind("//", 0) == 0 && line[1] == "client") {
            server_flag = false;
            client_flag = true;
            continue;
        }
        if (server_flag || client_flag) {
            std::string role = server_flag ? "server" : "client";
            if (line.size() == 2) {
                uint32_t index = get_from_param_map(&param_map, line[0]);
                uint32_t value = (uint32_t)std::stoi(line[1]);
                input_map[line[0]] = std::tuple<std::string, uint32_t, uint32_t>{role, value, index};
            } else if (line.size() > 2) {
                // Vector input, key_idx: value
                for (int i = 1; i < line.size(); i++) {
                    std::string key = line[0] + "_" + std::to_string(i-1);
                    uint32_t index = get_from_param_map(&param_map, key);
                    uint32_t value = (uint32_t)std::stoi(line[i]);
                    input_map[key] = std::tuple<std::string, uint32_t, uint32_t>{role, value, index};
                }
            }
        }
    }
    return input_map;
}


std::unordered_map<std::string, std::string> parse_share_map_file(std::string share_map_path) {
    std::ifstream file(share_map_path);
    assert(("Mapping file exists.", file.is_open()));
    if (!file.is_open()) throw std::runtime_error("Share map file doesn't exist. -- "+share_map_path);

    std::unordered_map<std::string, std::string> share_map;
    std::string str;
    bool role_flag = false;
    while (std::getline(file, str)) {
        std::vector<std::string> line = split(str, ' ');
        if (line.size() == 0) continue;
        if (line.size() == 2) {
            share_map[line[0]] = line[1];
        }
    }
    return share_map;
}

int main(int argc, char** argv) {
	e_role role; 
	uint32_t bitlen = 32, nvals = 31, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;
	seclvl seclvl = get_sec_lvl(secparam);

    argparse::ArgumentParser program("aby_interpreter");
    program.add_argument("-M", "--mode").required().help("Mode for parsing test inputs");
    program.add_argument("-R", "--role").required().help("Role: <Server:0 / Client:1>").scan<'i', int>();;
    program.add_argument("-b", "--bytecode").required().help("Bytecode");
    program.add_argument("-t", "--test").required().help("Test inputs");
    program.add_argument("-s", "--share_map").required().help("Map of share id to circuit type");
    program.add_argument("-p", "--param_map").required().help("Map of params to share id");
    program.parse_args(argc, argv);    // Example: ./main --color orange
    
    std::string m, bytecode_path, test_path, share_map_path, param_map_path;
    m = program.get<std::string>("--mode");  
    role = !program.get<int>("--role") ? SERVER : CLIENT;
    bytecode_path = program.get<std::string>("--bytecode");
    test_path = program.get<std::string>("--test");
    share_map_path = program.get<std::string>("--share_map");
    param_map_path = program.get<std::string>("--param_map");

	std::unordered_map<std::string, std::tuple<std::string, uint32_t, uint32_t>> params;
    std::unordered_map<std::string, std::string> share_map;
	switch(hash_mode(m)) {
        case mpc: {
            params = parse_mpc_inputs(test_path, param_map_path);
            share_map = parse_share_map_file(share_map_path);
        }
        break;
    }

	test_aby_test_circuit(bytecode_path, &params, &share_map, role, address, port, seclvl, 32,
			nthreads, mt_alg, S_BOOL);

	return 0;
}

