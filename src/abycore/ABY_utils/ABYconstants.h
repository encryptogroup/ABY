/**
 \file 		ABYconstants.h
 \author	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2019 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		File containing all ABY constants used throughout the source
 */

#ifndef _ABY_CONSTANTS_H_
#define _ABY_CONSTANTS_H_

#include <string>
#include <ENCRYPTO_utils/constants.h>

// Set to 1 for production. 1 will circumvent output reconstruction in the PrintValue and Assert gates, 0 prints these intermediate values.
#define ABY_PRODUCTION 0

//#define ABYDEBUG
//#define PRINT_OUTPUT
//#define DEBUGCOMM
#define DEBUGABYPARTY 0

#define PRINT_PERFORMANCE_STATS 0 //prints overall runtime statistics and gate counts
#define PRINT_COMMUNICATION_STATS 0 //prints communication statistics
#define BENCHONLINEPHASE 0 //show very detailed runtime statistic on each sharing for online phase, typically for troubleshooting

#define BENCH_HARDWARE 0 // measure RTT, connection bandwidth and AES

#define BATCH

//#define ABY_OT
//#define VERIFY_OT

#define ABY_PARTY_CHANNEL (MAX_NUM_COMM_CHANNELS-3)
#define ABY_SETUP_CHANNEL (ABY_PARTY_CHANNEL-1)
#define DJN_CHANNEL	32
#define DGK_CHANNEL DJN_CHANNEL

/**
 \def 	GARBLED_TABLE_WINDOW
 \brief	Window size of Yao's garbled circuits in pipelined execution
 */
#define GARBLED_TABLE_WINDOW 1024 * AES_BITS//1 * AES_BITS//1048575 //1048575 //=0xFFFFF for faster modulo operation
//                           ^^^^ = NUMOTBLOCKS

#define BATCH

#define FIXED_KEY_AES_HASHING //for OT routines
//#define USE_KK_OT
//#define USE_PIPELINED_AES_NI
//#define USE_KK_OT_FOR_MT
//#define GETCLEARVALUE_DEBUG
//#define DEBUGABYPARTY

#define USE_MULTI_MUX_GATES

// default directory containing ABY circuit files.
// can also be passed to ABYParty constructor at runtime
#define ABY_CIRCUIT_DIR "../../bin/circ/"

/**
 \enum 	e_role
 \brief	Defines the role of the party or the source / target for certain operations (e.g., input/output)
 */
enum e_role {
	SERVER, CLIENT, ALL
};

/**
 \enum	e_circuit_type
 \brief	Enumeration which defines the circuit type
 */
enum e_circuit {

	C_BOOLEAN = 0, /**< Enum for BOOLEAN circuit */
	C_ARITHMETIC = 1, /**< Enum for ARITHMETIC circuit */
	C_LAST = 2 /**< Dummy enum that is used to indicate the number of enums. DO NOT PUT ANOTHER ENUM AFTER THIS ONE! */
};

/**
 \enum	e_mt_gen_alg
 \brief	Enumeration which defines the method that is used for arithmetic multiplication triple generation.
 */
enum e_mt_gen_alg {

	MT_OT = 0, /**< Enum for using OT to generate arithmetic MTs */
	MT_PAILLIER = 1, /**< Enum for using PAILLIER to generate arithmetic MTs */
	MT_DGK = 2, /**< Enum for using DGK to generate arithmetic MTs */
	MT_LAST = 3 /**< Dummy enum that is used to indicate the number of enums. DO NOT PUT ANOTHER ENUM AFTER THIS ONE! */
};

/**
 \enum	e_gatetype
 \brief	Enumeration which defines the type of the gate in the circuit.
 */
enum e_gatetype {

	G_LIN = 0x00, /**< Enum for LINEAR gates (XOR in Boolean circuits, ADD in Arithmetic circuits) */
	G_NON_LIN = 0x01, /**< Enum for NON-LINEAR gates (AND in Boolean circuits, MUL in Arithmetic circuits) */
	G_NON_LIN_VEC = 0x02, /**< Enum for VECTOR-NON-LINEAR gates (AND-VEC in Boolsharing, MUL-VEC in Arithmeticsharing) */
	G_IN = 0x03, /**< Enum for INPUT gates */
	G_OUT = 0x04, /**< Enum for OUTPUT gates */
	G_INV = 0x05, /**< Enum for INVERSION gates */
	G_CONSTANT = 0x06, /**< Enum for CONSTANT gates */
	G_CONV = 0x07, /**< Enum for CONVERSION gates (dst is used to specify the sharing to convert to) */
	G_CALLBACK = 0x08, /**< Enum for Callback gates where the developer specifies a routine which is called upon gate evaluation */
	G_SHARED_OUT = 0x09, /**< Enum for shared output gate, where the output is kept secret-shared between parties after the evaluation*/
	G_TT = 0x0A, /**< Enum for computing an arbitrary truth table gate. Is needed for the 1ooN OT in SPLUT */
	G_SHARED_IN = 0x0B, /**< Enum for pre-shared input gate, where the parties dont secret-share (e.g. in outsourcing) */
	G_NON_LIN_CONST = 0x0C, /**< Enum for non-linear gate with a constant input (AND in boolean circuits, MUL in arithmetic circuits. One of the parents need to be a CONST gate */
	G_UNIV = 0x0D, /**< Enum for the Universal gate which can be parameterized to compute a specific 2 input 1 output Boolean function */
	G_PRINT_VAL = 0x40, /**< Enum gate that reconstructs the shares and prints the plaintext value with the designated string */
	G_ASSERT = 0x41, /**< Enum gate that reconstructs the shares and compares it to an provided input plaintext value */
	G_COMBINE = 0x80, /**< Enum for COMBINER gates that combine multiple single-value gates to one multi-value gate  */
	G_SPLIT = 0x81, /**< Enum for SPLITTER gates that split a multi-value gate to multiple single-value gates */
	G_REPEAT = 0x82, /**< Enum for REPEATER gates that repeat the value of a single-value gate to form a new multi-value gate */
	G_PERM = 0x83, /**< Enum for PERMUTATION gates that permute the value of multi-value gates */
	G_COMBINEPOS = 0x84, /**< Enum for COMBINE_AT_POSITION gates that form a new multi-value gate from specific positions of old multi-value gates */
	G_SUBSET = 0x85, /**< Enum for SUBSET gates that form a new multi-value gate from multiple positions of one multi-value gate */
	G_STRUCT_COMBINE = 0x86, /**< Enum for STRUCTURIZED COMBINER gates which combine one or multiple input gates based on an increase value*/
};

/**
 \enum 	e_operation
 \brief	Enumeration which defines all the operations which are there in the framework.
 */
enum e_operation {

	OP_XOR = 0, /**< Enum for performing LOGICAL XOR*/
	OP_AND = 1, /**< Enum for performing LOGICAL AND*/
	OP_ADD = 2, /**< Enum for performing ADDITION*/
	OP_MUL = 3, /**< Enum for performing MULTIPLICATION*/
	OP_CMP = 4, /**< Enum for performing COMPARISON*/
	OP_EQ = 5, /**< Enum for performing EQUALITY*/
	OP_MUX = 6, /**< Enum for performing MULTIPLEXER*/
	OP_SUB = 7, /**< Enum for performing SUBTRACTION*/
	OP_AND_VEC = 8, /**< Enum for performing VECTORED AND*/
	OP_MUL_VEC = 9, /**< Enum for performing VECTORED MULTIPLICATION*/
	OP_SHARE_OUT = 10, /**< Enum for Shared Output without reconstruction. */
	OP_SHARE_IN = 11, /**< Enum for Pre-Shared Input without input sharing (communication). */
	OP_TT = 12, /**< Enum for computing an arbitrary truth table. Is needed for the 1ooN OT in SPLUT */
	OP_IN, /**< Enum for performing INPUT*/
	OP_OUT, /**< Enum for performing OUTPUT*/
	OP_INV, /**< Enum for performing INVERSION*/
	OP_X,	/**<Enum for performing X SWITCHES>*/
	OP_UNIV,	/**<Enum for performing universal gates>*/
	OP_CONSTANT, /**< Enum for performing CONSTANT OPERATION*/
	OP_CONV, /**< Enum for performing CONVERSION*/
	OP_A2Y, /**< Enum for performing ARITHEMETIC TO YAO CONVERSION*/
	OP_B2A, /**< Enum for performing BOOL TO ARITHEMETIC CONVERSION*/
	OP_B2Y, /**< Enum for performing BOOL TO YAO CONVERSION*/
	OP_Y2B, /**< Enum for performing YAO TO BOOL CONVERSION*/
	OP_A2B, /**< Enum for performing ARITH TO BOOL CONVERSION*/
	OP_Y2A, /**< Enum for performing YAO TO ARITH CONVERSION*/
	OP_YSWITCH, /**< Enum for transferring roles in YAO sharing */
	OP_IO, /**< Enum for performing a SHARING followed by a RECONSTRUCT operation */
	OP_SBOX, /**< Enum for evaluating the AES S-box on an 8-bit input*/
	OP_PRINT_VAL = 0x40,/**< Enum for printing the plaintext output of a gate */
	OP_ASSERT = 0x41, /**< Enum for checking the plaintext output of a gate to a reference value */
	OP_COMBINE = 0x80, /**< Enum for COMBINING multiple single-value gates into one multi-gate */
	OP_SPLIT = 0x81, /**< Enum for SPLITTING one multi-value gate into multiple single-value gates */
	OP_REPEAT = 0x82, /**< Enum for REPEATING the value of a single-value gate to create a multi-value gate */
	OP_PERM = 0x83, /**< Enum for PERMUTING the values in a multi-value gate to another multi-value gate */
	OP_COMBINEPOS = 0x84 /**< Enum for COMBINING the values at specific positions in a multi-value gate */
};

/**
 \enum 	e_sharing
 \brief	Enumeration which defines the different sharing
 which are there in the framework.
 */
enum e_sharing {

	S_BOOL = 0, /**< Enum for performing bool sharing*/
	S_YAO = 1, /**< Enum for performing yao sharing*/
	S_ARITH = 2, /**< Enum for performing arithemetic sharing*/
	S_YAO_REV= 3, /**< Enum for performing yao sharing with reverse roles to enable inter-party parallelization (see Buescher et al. USENIX'15)*/
	S_SPLUT = 4, /**< Enum for the SP-LUT sharing */
	S_LAST = 5, /**< Enum for indicating the last enum value. DO NOT PUT ANOTHER ENUM AFTER THIS ONE! !*/

};

/**
	\def ePreCompPhase
	\brief Enumeration for pre-computation phase
*/
enum ePreCompPhase {
	ePreCompDefault = 0,
	ePreCompStore	= 1,
	ePreCompRead	= 2,
	ePreCompRAMWrite = 3,
	ePreCompRAMRead = -3
};

/**
 \struct 	aby_ops_t
 \brief	Holds the operation, a sharing and the string name of the operation
 */
typedef struct {
	e_operation op;
	e_sharing sharing;
	std::string opname;
} aby_ops_t;

inline std::string get_circuit_type_name(e_circuit c) {
	switch(c) {
	case C_BOOLEAN:
		return "BOOLEAN";
	case C_ARITHMETIC:
		return "ARITHMETIC";
	default:
		return "NN";
	}
}

inline std::string get_role_name(e_role r) {
	switch(r) {
	case SERVER:
		return "SERVER";
	case CLIENT:
		return "CLIENT";
	case ALL:
		return "ALL";
	default:
		return "NN";
	}
}

inline std::string get_sharing_name(e_sharing s) {
	switch (s) {
	case S_BOOL:
		return "Bool";
	case S_YAO:
		return "Yao";
	case S_YAO_REV:
		return "Reverse Yao";
	case S_ARITH:
		return "Arith";
	case S_SPLUT:
		return "SP-LUT";
	default:
		return "NN";
	}
}

inline std::string get_gate_type_name(e_gatetype g) {
	switch (g) {
	case G_LIN: return "Linear";
	case G_NON_LIN: return "Non-Linear";
	case G_NON_LIN_VEC: return "Vector-Non-Linear";
	case G_NON_LIN_CONST: return "Constant-Non-Linear";
	case G_IN: return "Input";
	case G_OUT: return "Output";
	case G_SHARED_OUT: return "Shared output";
	case G_INV: return "Inversion";
	case G_CONSTANT: return "Constant";
	case G_CONV: return "Conversion";
	case G_COMBINE: return "Combiner";
	case G_SPLIT: return "Splitter";
	case G_REPEAT: return "Repeater";
	case G_PERM: return "Permutation";
	case G_COMBINEPOS: return "Combiner-Position";
	case G_TT: return "Truth-Table";
	case G_ASSERT: return "Assertion";
	case G_PRINT_VAL: return "Printer";
	case G_UNIV: return "Universal";
	default: return "NN";
	}
}

///Operation type enum
typedef enum op_t{
    ADD, MUL, SUB, DIV, SIN, SQRT, EXP, EXP2, CMP, LN, LOG2, COS, SQR
}op_t;

// Floating point operation cinfiguration.
typedef enum fp_op_setting{
    ieee, no_status
}fp_op_setting;


inline std::string get_op_name(e_operation op) {
	switch (op) {
	case OP_XOR:
		return "XOR";
	case OP_AND:
		return "AND";
	case OP_ADD:
		return "ADD";
	case OP_AND_VEC:
		return "AND_VEC";
	case OP_SUB:
		return "SUB";
	case OP_MUL:
		return "MUL";
	case OP_MUL_VEC:
		return "MUL_VEC";
	case OP_CMP:
		return "CMP";
	case OP_EQ:
		return "EQ";
	case OP_MUX:
		return "MUX";
	case OP_X:
		return "X";
	case OP_UNIV:
		return "UNIV";
	case OP_IN:
		return "IN";
	case OP_OUT:
		return "OUT";
	case OP_INV:
		return "INV";
	case OP_CONSTANT:
		return "CONS";
	case OP_CONV:
		return "CONV";
	case OP_A2Y:
		return "A2Y";
	case OP_B2A:
		return "B2A";
	case OP_B2Y:
		return "B2Y";
	case OP_Y2B:
		return "Y2B";
	case OP_A2B:
		return "A2B";
	case OP_Y2A:
		return "Y2A";
	case OP_COMBINE:
		return "CMB";
	case OP_SPLIT:
		return "SPL";
	case OP_REPEAT:
		return "REP";
	case OP_PERM:
		return "PERM";
	case OP_COMBINEPOS:
		return "CMBP";
	default:
		return "NN";
	}
}


/** \var g_TruthTable
 \brief A truth-table for an AND gate
 */
constexpr uint8_t g_TruthTable[4] = { 0, 0, 0, 1 };		// and

/**\var m_vLUT_GT_IN
 * \brief Lookup-Table for the Greater-than functionality on input bits in No-MT sharing
 */
constexpr uint64_t m_vLUT_GT_IN[4][8] = {
		{0x86L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0x86005586L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0x5555555586005586L, 0x8600558600000000L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0x5555555586005586L, 0x8600558600000000L, 0x5555555555555555L, 0x5555555555555555L, 0x0L, 0x0L, 0x5555555586005586L, 0x8600558600000000L}};

/**\var m_vLUT_GT_INTERNAL
 * \brief Lookup-Table for the Greater-than functionality on internal bits in No-MT sharing
 */
constexpr uint64_t m_vLUT_GT_INTERNAL[3][8] = {
		{0xb1e45500, 0L, 0L, 0L, 0L, 0L, 0L, 0L},
		{0x5555555500000000L, 0xe4b10055b1e45500L, 0L, 0L, 0L, 0L, 0L, 0L},
		{0x0L, 0x0L, 0x5555555555555555L, 0x5555555555555555L, 0x5555555500000000L, 0xe4b10055b1e45500L, 0x55555555L, 0xb1e45500e4b10055L}};




/**\var m_vLUT_ADD_IN
 * \brief Lookup-Table for the addition functionality on inputs in No-MT sharing
 */
constexpr uint64_t m_vLUT_ADD_IN[4][24] = {
		{0x8L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0xb24a90a90200L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0x5444522052201000L, 0x5444522052201000L, 0x5444522052201000L, 0xdcccdaa8daa89888L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0x2080142080040000L, 0x8004000014410414L, 0x1441041420801420L, 0x2080142080040000L, 0x8824820814410414L, 0x34c30c34a28834a2L, 0x2080142080040000L, 0x8004000014410414L, 0x9649249524809524L, 0x2480952480040000L,
				0xa8a68a2896492495L, 0xb6cb2cb6aaa8b6aaL, 0x2080142080040000L, 0x8004000014410414L, 0x9649249524809524L, 0x2480952480040000L, 0xa8a68a2896492495L, 0xb6cb2cb6aaa8b6aaL,	0x28a09628a0860820L, 0xa086082096492496L,
				0x9649249628a09628L, 0x28a09628a0860820L, 0xa8a68a2896492496L, 0xb6cb2cb6aaa8b6aaL}
};

/**\var m_vLUT_ADD_N_OUTS
 * \brief Number of outputs for the m_vLUT_ADD_IN LUT
 */
constexpr uint32_t m_vLUT_ADD_N_OUTS[4] = {1, 3, 4, 6};


/**\var m_vLUT_ADD_INTERNAL
 * \brief Lookup-Table for the addition functionality on internal signals in No-MT sharing
 */
constexpr uint64_t m_vLUT_ADD_INTERNAL[2][16] = {
		{0xeeaae400L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0x3232222232100000L, 0x3232222232100000L, 0x3232222232100000L, 0x3232222232100000L, 0x3232222232100000L, 0xfafaaaaafa500000L, 0xbabaaaaaba988888L, 0xfafaaaaafad88888L,
				0xbabaaaaaba988888L, 0xbabaaaaaba988888L, 0xbabaaaaaba988888L, 0xbabaaaaaba988888L, 0xbabaaaaaba988888L, 0xfafaaaaafad88888L, 0xbabaaaaaba988888L, 0xfafaaaaafad88888L}
};

/**\var m_vLUT_ADD_CRIT_IN
 * \brief Lookup-Table for the addition functionality on the critical path where the inputs are real values in No-MT sharing
 */
constexpr uint64_t m_vLUT_ADD_CRIT_IN[4][16] = {
		{0x8L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0x3222300030001000L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0x200692600600200L, 0xe00200fb6e00e0L, 0xfb6f24f24b24fb6eL, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0x3222300030001000L, 0x7666700070001000L, 0x7666700070001000L, 0x7666744474445444L, 0x3222300030001000L, 0xfeeef000f0001000L, 0xfeeef000f0001000L, 0xfeeefcccfcccdcccL,
				0x3222300030001000L, 0xfeeef000f0001000L, 0xfeeef000f0001000L, 0xfeeefcccfcccdcccL,	0xbaaab888b8889888L, 0xfeeef888f8889888L, 0xfeeef888f8889888L, 0xfeeefcccfcccdcccL}
};

/**\var m_vLUT_ADD_CRIT
 * \brief Lookup-Table for the addition functionality on the critical path where the inputs are parity/carry signals in No-MT sharing
 */
constexpr uint64_t m_vLUT_ADD_CRIT[3][6] = {
		{0xf8L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0xffeaffeaffc05540L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0xb6926db600249200L, 0x2492006db6926dL, 0xffffb6ffffb6fffeL, 0xffb6ffff24b6db24L, 0x24b6db24ffffb6ffL, 0xffffb6ffffb6ffffL}
};

/**\var m_vLUT_ADD_INV
 * \brief Lookup-Table for the addition functionality on the inverse carry tree in No-MT sharing
 */
constexpr uint64_t m_vLUT_ADD_INV[3][6] = {
		{0xf8L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0xffeaffeaddc85540L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0xb692659610249200L, 0x302492006db6926dL, 0xffffb6ffffb6e79eL,	0xffb6f7df34b6db24L, 0x34b6db24ffffb6ffL, 0xffffb6ffffb6f7dfL}
};


/** \var m_tAllOps
 \brief All operations in the different sharings that are available in ABY
 */
static const aby_ops_t m_tAllOps[] = {
	{OP_IO, S_BOOL, "iobool"},
	{OP_XOR, S_BOOL, "xorbool"},
	{OP_AND, S_BOOL, "andbool"},
	{OP_ADD, S_BOOL, "addbool"},
	{OP_MUL, S_BOOL, "mulbool"},
	{OP_CMP, S_BOOL, "cmpbool"},
	{OP_EQ, S_BOOL, "eqbool"},
	{OP_MUX, S_BOOL, "muxbool"},
	{OP_SUB, S_BOOL, "subbool"},
	{OP_IO, S_YAO, "ioyao"},
	{OP_XOR, S_YAO, "xoryao"},
	{OP_AND, S_YAO, "andyao"},
	{OP_IO, S_ARITH, "ioarith"},
	{OP_ADD, S_YAO, "addyao"},
	{OP_MUL, S_YAO, "mulyao"},
	{OP_CMP, S_YAO, "cmpyao"},
	{OP_EQ, S_YAO, "eqyao"},
	{OP_MUX, S_YAO, "muxyao"},
	{OP_X, S_YAO, "xyao"},
	{OP_UNIV, S_YAO, "univyao"},
	{OP_SUB, S_YAO, "subyao"},
	{OP_ADD, S_ARITH, "addarith"},
	{OP_MUL, S_ARITH, "mularith"},
	{OP_Y2B, S_YAO, "y2b"},
	{OP_B2A, S_BOOL, "b2a"},
	{OP_B2Y, S_BOOL, "b2y"},
	{OP_A2Y, S_ARITH, "a2y"},
	{OP_A2B, S_ARITH, "a2b"},
	{OP_Y2A, S_YAO, "y2a"},
	{OP_AND_VEC, S_BOOL, "vec-and"},
	{OP_IO, S_SPLUT, "io1splut"},
	{OP_XOR, S_SPLUT, "xorsplut"},
	{OP_AND, S_SPLUT, "andsplut"},
	{OP_CMP, S_SPLUT, "cmpsplut"},
	{OP_ADD, S_SPLUT, "addsplut"},
	{OP_MUL, S_SPLUT, "mulsplut"},
	{OP_EQ, S_SPLUT, "eqsplut"},
	{OP_MUX, S_SPLUT, "muxsplut"},
	{OP_X, S_BOOL, "xbool"},
	{OP_UNIV, S_BOOL, "univbool"},
	{OP_SUB, S_SPLUT, "subsplut"}
};

#endif /* _ABY_CONSTANTS_H_ */
