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

#define AES_KEY_BITS			128
#define AES_KEY_BYTES			16
#define AES_BITS				128
#define AES_BYTES				16
#define LOG2_AES_BITS			ceil_log2(AES_BITS)

enum field_type {
	P_FIELD, ECC_FIELD
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

	G_LIN = 0, /**< Enum for LINEAR gates (XOR in Boolean circuits, ADD in Arithmetic circuits) */
	G_NON_LIN = 1, /**< Enum for NON-LINEAR gates (AND in Boolean circuits, MUL in Arithmetic circuits) */
	G_NON_LIN_VEC = 2, /**< Enum for VECTOR-NON-LINEAR gates (AND-VEC in Boolsharing, MUL-VEC in Arithmeticsharing) */
	G_IN = 3, /**< Enum for INPUT gates */
	G_OUT = 4, /**< Enum for OUTPUT gates */
	G_INV = 5, /**< Enum for INVERSION gates */
	G_CONSTANT = 6, /**< Enum for CONSTANT gates */
	G_CONV = 7, /**< Enum for CONVERSION gates (dst is used to specify the sharing to convert to) */
	G_COMBINE = 0x80, /**< Enum for COMBINER gates that combine multiple single-value gates to one multi-value gate  */
	G_SPLIT = 0x81, /**< Enum for SPLITTER gates that split a multi-value gate to multiple single-value gates */
	G_REPEAT = 0x82, /**< Enum for REPEATER gates that repeat the value of a single-value gate to form a new multi-value gate */
	G_PERM = 0x83, /**< Enum for PERMUTATION gates that permute the value of multi-value gates */
	G_COMBINEPOS = 0x84, /**< Enum for COMBINE_AT_POSITION gates that form a new multi-value gate from specific positions of old multi-value gates */
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
	OP_IN, /**< Enum for performing INPUT*/
	OP_OUT, /**< Enum for performing OUTPUT*/
	OP_INV, /**< Enum for performing INVERSION*/
	OP_CONSTANT, /**< Enum for performing CONSTANT OPERATION*/
	OP_CONV, /**< Enum for performing CONVERSION*/
	OP_A2Y, /**< Enum for performing ARITHEMETIC TO YAO CONVERSION*/
	OP_B2A, /**< Enum for performing BOOL TO ARITHEMETIC CONVERSION*/
	OP_B2Y, /**< Enum for performing BOOL TO YAO CONVERSION*/
	OP_Y2B, /**< Enum for performing YAO TO BOOL CONVERSION*/
	OP_IO, /**< Enum for performing a SHARING followed by a RECONSTRUCT operation */
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
	S_LAST = 3, /**< Enum for indicating the last enum value. DO NOT PUT ANOTHER ENUM AFTER THIS ONE! !*/
};

static string get_sharing_name(e_sharing s) {
	switch (s) {
	case S_BOOL:
		return "BOOL";
	case S_YAO:
		return "YAO";
	case S_ARITH:
		return "ARITH";
	default:
		return "NN";
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

#endif /* CONSTANTS_H_ */
