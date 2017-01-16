/**
 \file 		constants.h
 \author	michael.zohner@ec-spride.de
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
 \brief		File containing all constants used throughout the source
 */

#ifndef CONSTANTS_H_
#define CONSTANTS_H_

#include "typedefs.h"

/* Uncomment production to circumvent output reconstruction in the PrintValue and Assert gates */
//#define ABY_PRODUCTION

#define AES_KEY_BITS			128
#define AES_KEY_BYTES			16
#define AES_BITS				128
#define AES_BYTES				16
#define LOG2_AES_BITS			ceil_log2(AES_BITS)

#define SHA1_OUT_BYTES 20
#define SHA256_OUT_BYTES 32
#define SHA512_OUT_BYTES 64

#define MAX_NUM_COMM_CHANNELS 256
#define ADMIN_CHANNEL MAX_NUM_COMM_CHANNELS-1
#define OT_ADMIN_CHANNEL ADMIN_CHANNEL-1
#define ABY_PARTY_CHANNEL OT_ADMIN_CHANNEL-1
#define ABY_SETUP_CHANNEL ABY_PARTY_CHANNEL-1
#define DJN_CHANNEL	 32
#define DGK_CHANNEL DJN_CHANNEL
#define OT_BASE_CHANNEL 0

//Controls the number of OTs that are processed in one block. Lower values are better for lower latency networks.
#define NUMOTBLOCKS 128
#define BUFFER_OT_KEYS 128
/**
 \def 	GARBLED_TABLE_WINDOW
 \brief	Window size of Yao's garbled circuits in pipelined execution
 */
#define GARBLED_TABLE_WINDOW NUMOTBLOCKS * AES_BITS//1 * AES_BITS//1048575 //1048575 //=0xFFFFF for faster modulo operation


#define BATCH
#define ABY_OT
#define FIXED_KEY_AES_HASHING //for OT routines



/**
 \enum	field_type
 \brief	Enumeration for the field type of asymmetric cryptographic operations
 */
enum field_type {
	P_FIELD, ECC_FIELD, FIELD_LAST
};

static const seclvl ST = { 40, 80, 1024, 160, 163 };
static const seclvl MT = { 40, 112, 2048, 192, 233 };
static const seclvl LT = { 40, 128, 3072, 256, 283 };
static const seclvl XLT = { 40, 192, 7680, 384, 409 };
static const seclvl XXLT = { 40, 256, 15360, 512, 571 };

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
	G_TT = 0x0A, /**< Enum for computing an arbitrary truth table gate. Is needed for the 1ooN OT in BoolNonMTSharing */
	G_SHARED_IN = 0x0B, /**< Enum for pre-shared input gate, where the parties dont secret-share (e.g. in outsourcing) */
	G_PRINT_VAL = 0x40, /**< Enum gate that reconstructs the shares and prints the plaintext value with the designated string */
	G_ASSERT = 0x41, /**< Enum gate that reconstructs the shares and compares it to an provided input plaintext value */
	G_COMBINE = 0x80, /**< Enum for COMBINER gates that combine multiple single-value gates to one multi-value gate  */
	G_SPLIT = 0x81, /**< Enum for SPLITTER gates that split a multi-value gate to multiple single-value gates */
	G_REPEAT = 0x82, /**< Enum for REPEATER gates that repeat the value of a single-value gate to form a new multi-value gate */
	G_PERM = 0x83, /**< Enum for PERMUTATION gates that permute the value of multi-value gates */
	G_COMBINEPOS = 0x84, /**< Enum for COMBINE_AT_POSITION gates that form a new multi-value gate from specific positions of old multi-value gates */
	G_SUBSET = 0x85, /**< Enum for SUBSET gates that form a new multi-value gate from multiple positions of one multi-value gate */
	G_STRUCT_COMBINE = 0x86, /**< Enum for STRUCTURIZED COMBINER gates which combine one or multiple input gates based on an increase value*/
//G_YAO_BUILD 		/**< Enum for  */
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
	OP_TT = 12, /**< Enum for computing an arbitrary truth table. Is needed for the 1ooN OT in BoolNonMTSharing */
	OP_IN, /**< Enum for performing INPUT*/
	OP_OUT, /**< Enum for performing OUTPUT*/
	OP_INV, /**< Enum for performing INVERSION*/
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
	S_LAST = 4, /**< Enum for indicating the last enum value. DO NOT PUT ANOTHER ENUM AFTER THIS ONE! !*/
	S_BOOL_NO_MT = 5, /**< Enum for performing boolean sharing based on 1ooN OT */

};


/**
 \enum 	e_role
 \brief	Defines the role of the party or the source / target for certain operations (e.g., input/output)
 */
enum e_role {
	SERVER, CLIENT, ALL
};

/**
 \enum 	ot_ext_prot
 \brief	Specifies the different underlying OT extension protocols that are available
 */
enum ot_ext_prot {
	IKNP, ALSZ, NNOB, KK, PROT_LAST
};

/**
 \enum 	snd_ot_flavor
 \brief	Different OT flavors for the OT sender
 */
enum snd_ot_flavor {
	Snd_OT, Snd_C_OT, Snd_R_OT, Snd_GC_OT, Snd_OT_LAST
};

/**
 \enum 	rec_ot_flavor
 \brief	Different OT flavors for the OT receiver
 */
enum rec_ot_flavor {
	Rec_OT, Rec_R_OT, Rec_OT_LAST
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


static string get_circuit_type_name(e_circuit c) {
	switch(c) {
	case C_BOOLEAN:
		return "BOOLEAN";
	case C_ARITHMETIC:
		return "ARITHMETIC";
	default:
		return "NN";
	}
}


static string get_role_name(e_role r) {
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

static string get_sharing_name(e_sharing s) {
	switch (s) {
	case S_BOOL:
		return "Bool";
	case S_YAO:
		return "Yao";
	case S_YAO_REV:
		return "Reverse Yao";
	case S_ARITH:
		return "Arith";
	case S_BOOL_NO_MT:
		return "1ooN Bool";
	default:
		return "NN";
	}
}


static string get_gate_type_name(e_gatetype g) {
	switch (g) {
	case G_LIN: return "Linear";
	case G_NON_LIN: return "Non-Linear";
	case G_NON_LIN_VEC: return "Vector-Non-Linear";
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
	default: return "NN";
	}
}


static string get_op_name(e_operation op) {
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

static const char* getSndFlavor(snd_ot_flavor stype) {
	switch (stype) {
	case Snd_OT: return "Snd_OT";
	case Snd_C_OT: return "Snd_C_OT";
	case Snd_R_OT: return "Snd_R_OT";
	case Snd_GC_OT: return "Snd_GC_OT";
	default: return "unknown snd type";
	}
}

static const char* getRecFlavor(rec_ot_flavor rtype) {
	switch (rtype) {
	case Rec_OT: return "Rec_OT";
	case Rec_R_OT: return "Rec_R_OT";
	default: return "unknown rec type";
	}
}

static const char* getProt(ot_ext_prot prot) {
	switch (prot) {
	case IKNP: return "IKNP";
	case ALSZ: return "ALSZ";
	case NNOB: return "NNOB";
	case KK: return "KK";
	default: return "unknown protocol";
	}
}

static const char* getFieldType(field_type ftype) {
	switch (ftype) {
	case P_FIELD: return "P_FIELD";
	case ECC_FIELD: return "ECC_FIELD";
	default: return "unknown field";
	}
}

/** \var g_TruthTable
 \brief A truth-table for an AND gate
 */
const uint8_t g_TruthTable[4] = { 0, 0, 0, 1 };		// and
/** \var m_vFixedKeyAESSeed
 \brief The seed from which the key is generated
 */
const uint8_t m_vFixedKeyAESSeed[AES_KEY_BYTES] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
/** \var m_vSeed
 \brief Static seed for various testing functionalities
 */
const uint8_t m_vSeed[AES_KEY_BYTES] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

/**\var m_vLUT_GT_IN
 * \brief Lookup-Table for the Greater-than functionality on input bits in No-MT sharing
 */
const uint64_t m_vLUT_GT_IN[4][8] = {
		{0x2L, 0x9L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0x20f2, 0x9009L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0x20f20000ffff20f2L, 0x9009000000009009L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0x20f20000ffff20f2L, 0xffffffffffffffffL, 0x0L, 0x20f20000ffff20f2L, 0x9009000000009009L, 0x0L, 0x0L, 0x9009000000009009L}};

/**\var m_vLUT_GT_INTERNAL
 * \brief Lookup-Table for the Greater-than functionality on internal bits in No-MT sharing
 */
const uint64_t m_vLUT_GT_INTERNAL[3][8] = {
		{0x5af0L, 0xcc00L, 0L, 0L, 0L, 0L, 0L, 0L},
		{0xa50f5af0ffff0000L, 0xcc00cc0000000000L, 0L, 0L, 0L, 0L, 0L, 0L},
		{0x0L, 0xffffffffffffffffL, 0xa50f5af0ffff0000L, 0x5af0a50f0000ffffL, 0x0L, 0x0L, 0xcc00cc0000000000L, 0xcc00cc0000000000L}};




/**\var m_vLUT_ADD_IN
 * \brief Lookup-Table for the addition functionality on inputs in No-MT sharing
 */
const uint64_t m_vLUT_ADD_IN[4][24] = {
		{0x8L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0x8888L, 0x660L, 0xf880L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0x8888888888888888L, 0x660066006600660L, 0xf880f880f880f880L, 0xffff000000000000L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		//{0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0x8888888888888888L, 0x8888888888888888L, 0x8888888888888888L, 0x8888888888888888L, 0x660066006600660L, 0x660066006600660L, 0x660066006600660L, 0x660066006600660L,
				0xf880f880f880f880L, 0xf880f880f880f880L, 0xf880f880f880f880L, 0xf880f880f880f880L, 0xffff000000000000L, 0xffff000000000000L, 0xffff000000000000L, 0xffff000000000000L,
				0x0L, 0x66006600000L, 0x66006600000L, 0x0L, 0x0L, 0xfffff880f8800000L, 0xfffff880f8800000L, 0xffffffffffffffffL}
};

/**\var m_vLUT_ADD_N_OUTS
 * \brief Number of outputs for the m_vLUT_ADD_IN LUT
 */
const uint32_t m_vLUT_ADD_N_OUTS[4] = {1, 3, 4, 6};


/**\var m_vLUT_ADD_INTERNAL
 * \brief Lookup-Table for the addition functionality on internal signals in No-MT sharing
 */
const uint64_t m_vLUT_ADD_INTERNAL[2][16] = {
		{0xa0a0L, 0xffc0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0xa0a0a0a0a0a0a0a0L, 0xa0a0a0a0a0a0a0a0L, 0xa0a0a0a0a0a0a0a0L, 0xa0a0a0a0a0a0a0a0L, 0xffc0ffc0ffc0ffc0L, 0xffc0ffc0ffc0ffc0L, 0xffc0ffc0ffc0ffc0L, 0xffc0ffc0ffc0ffc0L,
				0x0L, 0xa0a00000a0a00000L, 0x0L, 0xa0a00000a0a00000L, 0x0L, 0xffffffffffc00000L, 0xffffffffffffffffL, 0xffffffffffffffffL}
};

/**\var m_vLUT_ADD_CRIT_IN
 * \brief Lookup-Table for the addition functionality on the critical path where the inputs are real values in No-MT sharing
 */
const uint64_t m_vLUT_ADD_CRIT_IN[4][16] = {
		{0x8L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0x8888L, 0xf880L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0x8888888888888888L, 0xf880f880f880f880L, 0xfffff880f8800000L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0x8888888888888888L, 0x8888888888888888L, 0x8888888888888888L, 0x8888888888888888L, 0xf880f880f880f880L, 0xf880f880f880f880L, 0xf880f880f880f880L, 0xf880f880f880f880L,
				0xfffff880f8800000L, 0xfffff880f8800000L, 0xfffff880f8800000L, 0xfffff880f8800000L, 0x0L, 0xfffff880f8800000L, 0xfffff880f8800000L, 0xffffffffffffffffL}
};

/**\var m_vLUT_ADD_CRIT
 * \brief Lookup-Table for the addition functionality on the critical path where the inputs are parity/carry signals in No-MT sharing
 */
const uint64_t m_vLUT_ADD_CRIT[3][6] = {
		{0xf8L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0xf8f8f8f8, 0xfffff800, 0x0L, 0x0L, 0x0L, 0x0L},
		{0xf8f8f8f8f8f8f8f8L, 0xf8f8f8f8f8f8f8f8L, 0xfffff800fffff800L, 0xfffff800fffff800L, 0xfffff80000000000L, 0xffffffffffffffffL}
};

/**\var m_vLUT_ADD_INV
 * \brief Lookup-Table for the addition functionality on the inverse carry tree in No-MT sharing
 */
const uint64_t m_vLUT_ADD_INV[3][6] = {
		{0xf8L, 0x0L, 0x0L, 0x0L, 0x0L, 0x0L},
		{0xf8f8f8f8, 0xffffaa00, 0x0L, 0x0L, 0x0L, 0x0L},
		{0xf8f8f8f8f8f8f8f8L, 0xf8f8f8f8f8f8f8f8L, 0xffffaa00ffffaa00L, 0xffffaa00ffffaa00L, 0xffffaa0000000000L, 0xffffffffffffffffL}
};


/** \var m_tAllOps
 \brief All operations in the different sharings that are available in ABY
 */
static const aby_ops_t m_tAllOps[] = {
//	{OP_IO, S_BOOL, "iobool"},
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
	{OP_SUB, S_YAO, "subyao"},
	{OP_ADD, S_ARITH, "addarith"},
	{OP_MUL, S_ARITH, "mularith"},
	{OP_Y2B, S_YAO, "y2b"},
	{OP_B2A, S_BOOL, "b2a"},
	{OP_B2Y, S_BOOL, "b2y"},
	{OP_A2Y, S_ARITH, "a2y"},
	{OP_A2B, S_ARITH, "a2b"},
	{OP_Y2A, S_YAO, "y2a"},
	{OP_AND_VEC, S_BOOL, "vec-and"}

//	{OP_IO, S_BOOL_NO_MT, "io1ooN"},
//	{OP_XOR, S_BOOL_NO_MT, "xor1ooN"},
//	{OP_AND, S_BOOL_NO_MT, "and1ooN"},
//	{OP_ADD, S_BOOL_NO_MT, "add1ooN"},
//	{OP_MUL, S_BOOL_NO_MT, "mul1ooN"},
//	{OP_CMP, S_BOOL_NO_MT, "cmp1ooN"},
//	{OP_EQ, S_BOOL_NO_MT, "eq1ooN"},
//	{OP_MUX, S_BOOL_NO_MT, "mux1ooN"},
//	{OP_SUB, S_BOOL_NO_MT, "sub1ooN"}
};

#endif /* CONSTANTS_H_ */
