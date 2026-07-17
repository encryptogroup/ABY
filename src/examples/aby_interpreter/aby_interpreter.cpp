#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
#include "../../abycore/aby/abyparty.h"
#include "common/aby_interpreter.h"

#include "argparse.hpp"
#include "util.h"

#include <filesystem>
#include <string>
#include <regex>

using namespace std::chrono;

enum mode {
    mpc
};

/** Cast string mode into mode enum
*
* @param m string mode
*
* @return mode enum
*/
mode hash_mode(std::string m) {
    if (m == "mpc") return mpc;
    throw std::invalid_argument("Unknown mode: "+m);
}

/** Get bytecode paths for each function
*
* @param path base path 
*
* @return map of function to bytecode path 
*/
std::unordered_map<std::string, std::string> get_bytecode_paths(std::string path) {
    std::unordered_map<std::string, std::string> map;
    auto path_list = split(path, "/");
    auto dirname = path_list[path_list.size() - 1];
    for (const auto & entry : std::filesystem::directory_iterator(path)) {
        std::string file_path{entry.path().u8string()};
        if (file_path.find("share_map.txt") != std::string::npos) {
            continue;
        }
        auto file_path_list = split(file_path, "/");
        auto filename = file_path_list[file_path_list.size() - 1];
        auto function_name = std::regex_replace(std::regex_replace(filename, std::regex(dirname+"_"), ""), std::regex("_bytecode.txt"), ""); 
        map[function_name] =  file_path;
    }
    return map;
}

/** Get assignment paths for each function
*
* @param share_map_path base path 
*
* @return map of function to assignment path
*/
std::unordered_map<std::string, std::string> parse_share_map_file(std::string share_map_path) {
    std::ifstream file(share_map_path);
    assert(("Mapping file exists.", file.is_open()));
    if (!file.is_open()) throw std::runtime_error("Share map file doesn't exist. -- "+share_map_path);
    std::unordered_map<std::string, std::string> share_map;
    std::string str;
    bool role_flag = false;
    while (std::getline(file, str)) {
        std::vector<std::string> line = split(str, " ");
        if (line.size() == 0) continue;
        if (line.size() == 2) {
            share_map[line[0]] = line[1];
        }
    }
    return share_map;
}

/** Get inputs 
*
* @param test_path test case path 
*
* @return map of input variables to test inputs
*/
std::unordered_map<std::string, uint32_t> parse_mpc_inputs(std::string test_path) {
    std::ifstream file(test_path);
    assert(("Test file exists.", file.is_open()));
    if (!file.is_open()) throw std::runtime_error("Test file doesn't exist.");
    std::unordered_map<std::string, uint32_t> map;
    std::string str;
    uint32_t num_params = 0;
    while (std::getline(file, str)) {
        std::vector<std::string> line = split(str, " ");
        std::string key_ = line[0];
        if (key_ == "res") continue;
        if (line.size() == 2) {
            std::string key = line[0];
            uint32_t value = (uint32_t)std::stoi(line[1]);
            map[key] = value;
        } else if (line.size() > 2) {
            // Input arrays 
            for (int i = 1; i < line.size(); i++) {
                std::string key = line[0] + "_" + std::to_string(i-1);
                uint32_t value = (uint32_t)std::stoi(line[i]);
                map[key] = value;
            }
        }
    }
    return map;
}

int main(int argc, char** argv) {
    // add timing code
	high_resolution_clock::time_point start_total_time = high_resolution_clock::now();

    // initial parameters 
	e_role role; 
	uint32_t bitlen = 32, nvals = 31, secparam = 128, nthreads = 1;
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;
	seclvl seclvl = get_sec_lvl(secparam);

    // parse cmdline args 
    argparse::ArgumentParser program("aby_interpreter");
    program.add_argument("-m", "--mode").required().help("Mode for parsing test inputs");
    program.add_argument("-r", "--role").required().help("Role: <Server:0 / Client:1>").scan<'i', int>();
    program.add_argument("-f", "--file").required().help("File");
    program.add_argument("-t", "--test").required().help("Test inputs");
    program.add_argument("-a", "--address").required().help("Address").default_value(std::string{"127.0.0.1"});
    program.add_argument("-p", "--port").required().help("Port").scan<'i', int>().default_value(7766);;
    program.parse_args(argc, argv);    // Example: ./main --color orange
    
    std::string m, path, test_path;
    m = program.get<std::string>("--mode");  
    role = !program.get<int>("--role") ? SERVER : CLIENT;
    path = program.get<std::string>("--file");
    test_path = program.get<std::string>("--test");
	std::string address = program.get<std::string>("--address");
    uint16_t port = program.get<int>("--port");

    // initialize param, share_map, and bytecode_paths maps 
	std::unordered_map<std::string, uint32_t> params;
    std::unordered_map<std::string, std::string> share_map;
    std::unordered_map<std::string, std::string> bytecode_paths;

    // get paths 
    auto share_map_path = get_path(path, "_share_map.txt");
    auto const_path = get_path(path, "_const.txt");
    bytecode_paths = get_bytecode_paths(path);
    
    // parse inputs
	switch(hash_mode(m)) {
        case mpc: {
            params = parse_mpc_inputs(test_path);
            share_map = parse_share_map_file(share_map_path);
        }
        break;
    }

    // interpret circuit
	double exec_time = interpret_circuit(&bytecode_paths, const_path, &params, &share_map, role, address, port, seclvl, 32,
			nthreads, mt_alg, S_BOOL);

    // add timing code
    high_resolution_clock::time_point end_total_time = high_resolution_clock::now();
	duration<double> total_time = duration_cast<duration<double>>(end_total_time - start_total_time);
    std::cout << "LOG: " << (role == SERVER ? "Server load time: " : "Client load time: ") << total_time.count() - exec_time << std::endl;
	std::cout << "LOG: " << (role == SERVER ? "Server total time: " : "Client total time: ") << total_time.count() << std::endl;

	return 0;
}

