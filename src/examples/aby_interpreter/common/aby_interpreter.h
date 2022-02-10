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

int32_t test_aby_test_circuit(std::string bytecode_file_path, std::unordered_map<std::string, int> params, e_role role, const std::string& address, 
		uint16_t port, seclvl seclvl, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing);