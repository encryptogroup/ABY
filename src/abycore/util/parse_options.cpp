/**
 \file 		parse_options.cpp
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

#include "parse_options.h"

/**
 * takes a string in the Format "i|i|i|..."
 * (integers separated by '|') and returns a vector of all integers
 * @param str the string to tokenize
 * @param tokens the result vector of wire id
 */
void tokenize(const std::string& str, std::vector<uint32_t>& tokens, const std::string& delimiters) {

	tokens.clear();

	// Skip delimiters at beginning
	std::string::size_type lastPos = str.find_first_not_of(delimiters, 0);

	// Find first "non-delimiter".
	std::string::size_type pos = str.find_first_of(delimiters, lastPos);

	while (std::string::npos != pos || std::string::npos != lastPos) {
		// Found a token, add it to the vector.
		tokens.push_back(atoi(str.substr(lastPos, pos - lastPos).c_str()));
		// Skip delimiters.  Note the "not_of"
		lastPos = str.find_first_not_of(delimiters, pos);
		// Find next "non-delimiter"
		pos = str.find_first_of(delimiters, lastPos);
	}
}

int32_t parse_options(int32_t* argcp, char*** argvp, parsing_ctx* options, uint32_t nops) {
	int result = 0;
	bool skip;
	uint32_t i;
	if(*argcp < 2)
		return 0;

	while ((*argcp) > 1) {
		if ((*argvp)[1][0] != '-' || (*argvp)[1][1] == '\0' || (*argvp)[1][2] != '\0')
			return result;
		for (i = 0, skip = false; i < nops && !skip; i++) {
			if (((*argvp)[1][1]) == options[i].opt_name) {

				switch (options[i].type) {
				case T_NUM:
					if (isdigit((*argvp)[2][0])) {
						++*argvp;
						--*argcp;
						*((uint32_t*) options[i].val) = atoi((*argvp)[1]);
					}
					break;
				case T_DOUBLE:
					++*argvp;
					--*argcp;
					*((double*) options[i].val) = atof((*argvp)[1]);
					break;
				case T_STR:
					++*argvp;
					--*argcp;
					*((std::string*) options[i].val) = (*argvp)[1];
					break;
				case T_FLAG:
					*((bool*) options[i].val) = true;
					break;
				}
				++result;
				++*argvp;
				--*argcp;
				options[i].set = true;
				skip = true;
			}
		}
	}

	for (i = 0; i < nops; i++) {
		if (options[i].required && !options[i].set)
			return 0;
	}
	return 1;
}

void print_usage(std::string progname, parsing_ctx* options, uint32_t nops) {
	uint32_t i;
	std::cout << "Usage: " << progname << std::endl;
	for (i = 0; i < nops; i++) {
		std::cout << " -" << options[i].opt_name << " [" << options[i].help_str << (options[i].required ? ", required" : ", optional") << "]" << std::endl;
	}
	std::cout << std::endl << "Program exiting" << std::endl;
}

