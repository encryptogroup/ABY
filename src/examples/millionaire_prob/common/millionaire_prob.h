/**
 \file 		millionaire_prob.h
 \author 	Sreeram Sadasivam
 \copyright __________________
 \brief		Implementation of the millionaire problem using ABY Framework.
 */

#ifndef __MILLIONAIREPROB_H_
#define __MILLIONAIREPROB_H_

#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/circuit/arithmeticcircuits.h"
#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include <math.h>
#include <cassert>

#define ALICE 	"ALICE"
#define BOB 	"BOB"

/**
 \param		role 		role played by the program which can be server or client part.
 \param 	address 	IP Address
 \param 	seclvl 		Security level
 \param 	nvals		Number of values
 \param 	bitlen		Bit length of the inputs
 \param 	nthreads	Number of threads
 \param		mt_alg		The algorithm for generation of multiplication triples
 \param 	sharing		Sharing type object
 \brief		This function is used for running a testing environment for solving the
 millionaire's problem
 */
int32_t test_millionaire_prob_circuit(e_role role, char* address, seclvl seclvl, uint32_t nvals, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing);

/**
 \param		s_alice		shared object of alice.
 \param		s_bob 		shared object of bob.
 \param		bc	 		boolean circuit object.
 \brief		This function is used to build and solve the millionaire's problem.
 */
share* BuildMillionaireProbCircuit(share *s_alice, share *s_bob, BooleanCircuit *bc);

static uint32_t m_nBitLength;

#endif /* __MILLIONAIREPROB_H_ */
