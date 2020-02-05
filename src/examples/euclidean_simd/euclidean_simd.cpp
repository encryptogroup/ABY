/**
 \file 		addition_test.cpp
 \author	romalvarezllorens@gmail.com
 */
#include <vector>
#include <iterator>
#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/erase.hpp>
#include <string>
#include <iostream>
#include <iomanip>
#include <fstream>

#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
#include "../../abycore/aby/abyparty.h"
#include "common/euclidean_simd.h"
 

/**To be able to use to_string() method*/
namespace patch
{
    template < typename T > std::string to_string( const T& n )
    {
        std::ostringstream stm ;
        stm << n ;
        return stm.str() ;
    }
}

 int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role,
		uint32_t* bitlen, uint32_t* nvals, uint32_t* secparam, std::string* address,
		uint16_t* port, int32_t* test_op) {

	uint32_t int_role = 0, int_port = 0;

	parsing_ctx options[] =
			{ { (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false }, {
					(void*) nvals, T_NUM, "n",
					"Number of parallel operation elements", false, false }, {
					(void*) bitlen, T_NUM, "b", "Bit-length, default 32", false,
					false }, { (void*) secparam, T_NUM, "s",
					"Symmetric Security Bits, default: 128", false, false }, {
					(void*) address, T_STR, "a",
					"IP-address, default: localhost", false, false }, {
					(void*) &int_port, T_NUM, "p", "Port, default: 7766", false,
					false }, { (void*) test_op, T_NUM, "t",
					"Single test (leave out for all operations), default: off",
					false, false } };

	if (!parse_options(argcp, argvp, options,
			sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		std::cout << "Exiting" << std::endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (e_role) int_role;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	return 1;
}

class CSVReader
{
	std::string fileName;
	std::string delimeter;
 
public:
	CSVReader(std::string filename, std::string delm = ",") :
			fileName(filename), delimeter(delm)
	{ }
 
	// Function to fetch data from a CSV File
	std::vector<std::vector<std::string> > getData();
};
 
/*
* Parses through csv file line by line and returns the data
* in vector of vector of strings.
*/




std::vector<std::vector<std::string> > CSVReader::getData()
{
	std::ifstream file(fileName);
 
	std::vector<std::vector<std::string> > dataList;
 
	std::string line = "";
	// Iterate through each line and split the content using delimeter
	//  UNCOMMENT if there are HEADERS in order to not include them in the vectors
	//std::getline(file,line);
	
	while ( (std::getline(file, line)) )
	{		
		std::vector<std::string> vec;
		//REMOVING DOUBLE QUOTES IF ANY
		line.erase(std::remove(line.begin(),line.end(),'\"'),line.end());
		//boost::erase_all(line, "\"");
		//std::cout<< line<< " "<<std::endl;
		boost::algorithm::split(vec,line, boost::is_any_of(delimeter));
		dataList.push_back(vec);		

	}
	// Close the File
	file.close();
	return dataList;
}
  

int main(int argc, char** argv) {
	e_role role;
	uint32_t bitlen = 32, nvals = 31, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;

	read_test_options(&argc, &argv, &role, &bitlen, &nvals, &secparam, &address,
			&port, &test_op);

	seclvl seclvl = get_sec_lvl(secparam);
	std::string filename;
	std::vector<long>  x_start;
	std::vector<long> y_start;
	std::vector<long> x_end;
	std::vector<long> y_end;
	int n_columns=0;

	//* 
	if(role == SERVER){
		filename = "/root/ABY/data_test/data1.csv";
	}else {
		filename = "/root/ABY/data_test/data2.csv";
	}
	

	CSVReader reader(filename);
	std::vector<std::vector<std::string> > dataList = reader.getData();

	for(std::vector<std::string> vec : dataList){
		//stol --> string to long
		x_start.push_back(std::stol (vec.at(0),nullptr,10));
		y_start.push_back(std::stol (vec.at(1),nullptr,10));
		x_end.push_back(std::stol (vec.at(2),nullptr,10));
		y_end.push_back(std::stol (vec.at(3),nullptr,10));
		n_columns++;
		
	}
				
	//evaluate addition cirucui using arithmetic
	test_circuit(role, address, port, seclvl, bitlen,
			nthreads, mt_alg, S_BOOL, x_start, y_start,x_end, y_end);           
	
	return 0;
}
