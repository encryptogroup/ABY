#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>

#include "../../abycore/aby/abyparty.h"

#include "common/aby_interpreter.h"

enum mode {
    mpc
};

mode hash(std::string m) {
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

std::unordered_map<std::string, std::pair<uint32_t, std::string>> parse_mpc_inputs(std::string test_file_path) {
    std::unordered_map<std::string, std::pair<uint32_t, std::string>> input_map;

    std::ifstream file(test_file_path);
    assert(("Test file exists.", file.is_open()));

    std::string str;
    bool server_flag = false;
    bool client_flag = false;
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
            std::string flag = server_flag ? "server" : "client";
            if (line.size() == 2) {
                input_map[line[0]] = std::pair{(uint32_t)std::stoi(line[1]),flag};
            } else if (line.size() > 2) {
                // Vector input, key_idx: value
                for (int i = 1; i < line.size(); i++) {
                    std::string key = line[0] + "_" + std::to_string(i-1);
                    input_map[key] = std::pair{(uint32_t)std::stoi(line[i]),flag};
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


void check_inputs(std::string m, std::string bytecode_file_path, std::string test_file_path, std::string mapping_file_path) {
    if (m.empty()) {
        std::cout << "Please specify the mode: mpc" << std::endl;
        exit(1);
    }
    
    if (bytecode_file_path.empty()) {
        std::cout << "Please specify the bytecode file path." << std::endl;
        exit(1);
    }

    if (test_file_path.empty()) {
        std::cout << "Please specify the test file path." << std::endl;
        exit(1);
    }

    if (mapping_file_path.empty()) {
        std::cout << "Please specify the mapping file path." << std::endl;
        exit(1);
    }
}


int main(int argc, char** argv) {
	e_role role; 
	uint32_t bitlen = 32, nvals = 31, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;
	seclvl seclvl = get_sec_lvl(secparam);

	std::vector<std::string> args(argv + 1, argv + argc);
    std::string m, bytecode_file_path, test_file_path, mapping_file_path;
    for (auto i = args.begin(); i != args.end(); ++i) {
        if (*i == "-m" || *i == "--mode") {
            m = *++i;
        } else if (*i == "-r" || *i == "--role") {
            role = (e_role) std::stoi(*++i);
        } else if (*i == "-t" || *i == "--test_file") {
            test_file_path = *++i;
        } else if (*i == "-b" || *i == "--bytecode_file") {
            bytecode_file_path = *++i;
        } else if (*i == "-m" || *i == "--mapping_file") {
            mapping_file_path = *++i;
        }
    }

    check_inputs(m, bytecode_file_path, test_file_path, mapping_file_path);

	std::unordered_map<std::string, std::pair<uint32_t, std::string>> params;
    std::unordered_map<std::string, std::string> mapping;	

	switch(hash(m)) {
        case mpc: {
            params = parse_mpc_inputs(test_file_path);
            mapping = parse_mapping_file(mapping_file_path);
        }
        break;
    }

	test_aby_test_circuit(bytecode_file_path, params, mapping, role, address, port, seclvl, 32,
			nthreads, mt_alg, S_BOOL);

	return 0;
}

