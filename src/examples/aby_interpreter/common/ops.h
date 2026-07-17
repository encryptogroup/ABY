/**
 * @file ops.h
 *
 * @brief This file defines all operations used by the ABY interpreter and 
 * relevant helper functions.
 *
 */


enum op {
	ADD_,
	SUB_,
	MUL_,
	EQ_,
	GT_,
	LT_,
	GE_,
	LE_,
	REM_,
	AND_,
	OR_,
	XOR_,
	CONS_,
	MUX_, 
	NOT_,
	SHL_,
	LSHR_,
	DIV_,
	STORE_,
	SELECT_,
	IN_,
	OUT_,
	CALL_
};

/** Check op is a call operator
*
* @param op term operator
*
* @return true if call op, otherwise false
*/
bool is_call_op(std::string op) {
	if (op.find("CALL") != std::string::npos) {
		return true;
	}
	return false;
}

/** Check op is a binary operator
*
* @param op term operator
*
* @return true if binary op, otherwise false
*/
bool is_bin_op(op o) {
	return o == ADD_ || o == SUB_ || o == MUL_ || o == EQ_ || o == GT_ || o == LT_ || o == GE_ || o == LE_ || o == REM_ || o == DIV_ || o == AND_ || o == OR_ || o == XOR_;
}

/** Cast string operator into op enum
*
* @param op string operator
*
* @return op enum
*/
op op_hash(std::string o) {
    if (o == "ADD") return ADD_;
	if (o == "SUB") return SUB_;
	if (o == "MUL") return MUL_;
	if (o == "EQ") return EQ_;
	if (o == "GT") return GT_;
	if (o == "LT") return LT_;
	if (o == "GE") return GE_;
	if (o == "LE") return LE_;
	if (o == "REM") return REM_;
	if (o == "AND") return AND_;
	if (o == "OR") return OR_;
	if (o == "XOR") return XOR_;
	if (o == "CONS") return CONS_;
	if (o == "MUX") return MUX_;
	if (o == "NOT") return NOT_;
	if (o == "DIV") return DIV_;
	if (o == "SHL") return SHL_;
	if (o == "LSHR") return LSHR_;
	if (o == "IN") return IN_;
	if (o == "OUT") return OUT_;
	if (o == "SELECT") return SELECT_;
	if (o == "STORE") return STORE_;
	if (is_call_op(o)) return CALL_;
    throw std::invalid_argument("Unknown operator: "+o);
}

/** Parse the function name from a call op
*
* @param op string operator
*
* @return function name 
*/
std::string parse_fn_name(std::string op) {
	assert(("Op is call op", is_call_op(op)));
	
	std::regex rex("\\((.*)\\)");
    std::smatch m;
    if (regex_search(op, m, rex)) {
       return m[1];
	} else {
		throw std::invalid_argument("Unable to parse function name out of Call op: "+op);
	}
}