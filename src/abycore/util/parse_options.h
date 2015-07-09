/**
 \file 		parse_options.h
 \author 	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2015 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
			it under the terms of the GNU Affero General Public License as published
			by the Free Software Foundation, either version 3 of the License, or
			(at your option) any later version.
			This program is distributed in the hope that it will be useful,
			but WITHOUT ANY WARRANTY; without even the implied warranty of
			MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
			GNU Affero General Public License for more details.
			You should have received a copy of the GNU Affero General Public License
			along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Parse Options Implementation
 */

#ifndef UTIL_PARSE_OPTIONS_H_
#define UTIL_PARSE_OPTIONS_H_

#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <stdint.h>
#include <vector>

enum etype {
	T_NUM, T_STR, T_FLAG, T_DOUBLE
};

typedef struct {
	void* val;
	etype type;
	char opt_name;
	std::string help_str;
	bool required;
	bool set;
} parsing_ctx;

int32_t parse_options(int32_t* argcp, char*** argvp, parsing_ctx* options, uint32_t nops);
void print_usage(std::string progname, parsing_ctx* options, uint32_t nops);
void tokenize(const std::string& str, std::vector<uint32_t>& tokens, const std::string& delimiters = "| \t");
void tokenize_verilog(const std::string& str, std::vector<uint32_t>& tokens, const std::string& delimiters = " \t");

#endif /* PARSE_OPTIONS_H_ */
