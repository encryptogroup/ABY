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

std::unordered_map<std::string, std::tuple<std::string, uint32_t, uint32_t>> parse_mpc_inputs(std::string test_file_path) {
    std::unordered_map<std::string, std::tuple<std::string, uint32_t, uint32_t>> input_map;
    std::ifstream file(test_file_path);
    assert(("Test file exists.", file.is_open()));
    std::string str;
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
            uint32_t value = (uint32_t)std::stoi(line[1]);
            uint32_t index = num_params;
            num_params++;
            if (line.size() == 2) {
                input_map[line[0]] = std::tuple<std::string, uint32_t, uint32_t>{role, value, index};
            } else if (line.size() > 2) {
                // Vector input, key_idx: value
                for (int i = 1; i < line.size(); i++) {
                    std::string key = line[0] + "_" + std::to_string(i-1);
                    input_map[key] = std::tuple<std::string, uint32_t, uint32_t>{role, value, index};
                }
            }
        }
    }
    return input_map;
}


std::unordered_map<std::string, std::string> parse_mapping_file(std::string mapping_file_path) {
    std::unordered_map<std::string, std::string> mapping_map;
    std::ifstream file(mapping_file_path);
    assert(("Mapping file exists.", file.is_open()));
    std::string str;
    bool role_flag = false;
    while (std::getline(file, str)) {
        std::vector<std::string> line = split(str, ' ');
        if (line.size() == 0) continue;
        if (line.size() == 2) {
            mapping_map[line[0]] = line[1];
        }
    }
    return mapping_map;
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
    program.add_argument("-b", "--bytecode").required().help("Bytecode file");
    program.add_argument("-t", "--test").required().help("Test inputs file");
    program.add_argument("-m", "--mapping").required().help("Mapping of shares to circuit type file");

	try {
        program.parse_args(argc, argv);    // Example: ./main --color orange
    }
        catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }

    std::string m, bytecode_path, test_path, mapping_path;
    m = program.get<std::string>("--mode");  
    role = !program.get<int>("--role") ? SERVER : CLIENT;
    bytecode_path = program.get<std::string>("--bytecode");
    test_path = program.get<std::string>("--test");
    mapping_path = program.get<std::string>("--mapping");

	std::unordered_map<std::string, std::tuple<std::string, uint32_t, uint32_t>> params;
    std::unordered_map<std::string, std::string> mapping;
	switch(hash_mode(m)) {
        case mpc: {
            params = parse_mpc_inputs(test_path);
            mapping = parse_mapping_file(mapping_path);
        }
        break;
    }

	test_aby_test_circuit(bytecode_path, &params, &mapping, role, address, port, seclvl, 32,
			nthreads, mt_alg, S_BOOL);

	return 0;
}

