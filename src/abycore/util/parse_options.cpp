/**
 \file 		parse_options.cpp
 \author 	michael.zohner@ec-spride.de
 \copyright __________________
 \brief		Parse Options Implementation
 */

#include "parse_options.h"

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
		std::cout << " -" << options[i].opt_name << " [" << options[i].help_str << "]" << std::endl;
	}
	std::cout << std::endl << "Program exiting" << std::endl;
}

