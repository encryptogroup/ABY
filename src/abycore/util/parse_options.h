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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <stdint.h>
#include <vector>

/**
 \enum 	etype
 \brief	Data types for command line parameters
 */
enum etype {
	T_NUM, //uint32_t number
	T_STR, //string
	T_FLAG, //boolean flag
	T_DOUBLE //double number
};


/**
 \struct 	parsing_ctx
 \brief	holds information about parameters that should be parsed in the command line input
 */
typedef struct {
	void* val;	//value of the option, is written into by parse_options
	etype type;	//type of value
	std::string opt_name; //name to set the parameter via command line
	std::string help_str; //definition of the parameter that is printed in print_usage
	bool required; //is the parameter required to run the program? If required and not set by the invocation, program will exit
	bool set; //has the value for the parameter been set previously? In case the parameter is read, this will be set to true
} parsing_ctx;


/**
	This method parses the command line arguments from a C program, given in argcp and argcv, using the flags and parameters specified
	in options where nops gives the number of parameters that are parsed. The values for the parameters are written into options.

	\param  argcp	 - Pointer to argc
	\param  argvp	 - Pointer to argv
	\param	options  - A list of parameters that the command line input should be parsed for
	\param	nops	 - Number of parameters in options
	\return	0 if the command line string was faulty and 1 otherwise.
*/
int32_t parse_options(int32_t* argcp, char*** argvp, parsing_ctx* options, uint32_t nops);

/**
	This method prints the command line parameters together with a short help description in help_str

	\param  progname	- Name of the program
	\param  options		- Parameters that should be printed
	\param	nops	 	- Number of parameters in options

*/
void print_usage(std::string progname, parsing_ctx* options, uint32_t nops);
void tokenize(const std::string& str, std::vector<uint32_t>& tokens, const std::string& delimiters = "| \t");
void tokenize_verilog(const std::string& str, std::vector<uint32_t>& tokens, const std::string& delimiters = " \t");

#endif /* PARSE_OPTIONS_H_ */
