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


std::unordered_map<std::string, int> parse_mpc_inputs(std::string test_file_path, int role) {
    std::unordered_map<std::string, int> input_map;

    std::ifstream file(test_file_path);
    assert(("Test file exists.", file.is_open()));

    std::string str;
    bool role_flag = false;
    while (std::getline(file, str)) {
        std::vector<std::string> line = split(str, ' ');
        if (line.size() == 0) continue;
        if (line[0].rfind("//", 0) == 0) {
            role_flag = false;
        }
        if (line[0].rfind("//", 0) == 0 && line[1] == "server") {
            if (role == 0) role_flag = true;
            if (role == 1) role_flag = false;
            continue;
        }
        if (line[0].rfind("//", 0) == 0 && line[1] == "client") {
            if (role == 1) role_flag = true;
            if (role == 0) role_flag = false;
            continue;
        }
        if (role_flag) {
            if (line.size() == 2) {
                input_map[line[0]] = std::stoi(line[1]);
            } else if (line.size() > 2) {
                // Vector input, key_idx: value
                for (int i = 1; i < line.size(); i++) {
                    std::string key = line[0] + "_" + std::to_string(i-1);
                    input_map[key] = std::stoi(line[i]);
                }
            }
        }
    }
    return input_map;
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
    std::string m, bytecode_file_path, test_file_path;
    for (auto i = args.begin(); i != args.end(); ++i) {
        if (*i == "-m" || *i == "--mode") {
            m = *++i;
        } else if (*i == "-r" || *i == "--role") {
            role = (e_role) std::stoi(*++i);
        } else if (*i == "-t" || *i == "--test_file") {
            test_file_path = *++i;
        } else if (*i == "-f" || *i == "--file") {
            bytecode_file_path = *++i;
        }
    }

	std::unordered_map<std::string, int> params;
	
	switch(hash(m)) {
        case mpc: {
            params = parse_mpc_inputs(test_file_path, (int) role);
        }
        break;
    }

	test_aby_test_circuit(bytecode_file_path, params, role, address, port, seclvl, 32,
			nthreads, mt_alg, S_BOOL);

	return 0;
}

