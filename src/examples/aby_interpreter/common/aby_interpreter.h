#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/circuit/arithmeticcircuits.h"
#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include <math.h>
#include <cassert>
#include <stdio.h>
#include <ctype.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <vector>
#include <bits/stdc++.h>
#include <ctime>
#include <ratio>
#include <chrono>

double interpret_circuit(
	std::unordered_map<std::string, std::string>* bytecode_paths, 
	std::string const_path,
	std::unordered_map<std::string, uint32_t>* params, 
	std::unordered_map<std::string, std::string>* share_map,
	e_role role, const std::string& address, 
	uint16_t port, 
	seclvl seclvl, 
	uint32_t bitlen, 
	uint32_t nthreads, 
	e_mt_gen_alg mt_alg, 
	e_sharing sharing
);
