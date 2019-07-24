/**
 \file 		sharing.h
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
 \brief		Sharing class.
 A virtual class that contains the methods which the sharing
 schemes have to implement
 */

#ifndef __SHARING_H__
#define __SHARING_H__

#include <ENCRYPTO_utils/cbitvector.h>
#include "../ABY_utils/ABYconstants.h"
#include <cstdint>
#include <vector>
//#define DEBUGSHARING

class ABYCircuit;
class ABYSetup;
class Circuit;
class crypto;
struct GATE;
struct UGATE;


/**
 Generic class for specifying different types of sharing.
 */
class Sharing {
public:
	/**
	 \param 		role 			Specifying the role....
	 \param 		sharebitlen 	Bit Length of share
	 \param 		circuit 		circuit object
	 \param 		crypt 			crypto object

	 \brief 		Initialises the members of the class.
	 */
	Sharing(e_sharing context, e_role role, uint32_t sharebitlen, ABYCircuit* circuit, crypto* crypt, const std::string& circdir = ABY_CIRCUIT_DIR);

	/**
	 Destructor of class.
	 */
	virtual ~Sharing();

	/**	Reset method */
	virtual void Reset() = 0;

	/*
	Note: PrepareSetupPhase, PerformSetupPhase, FinishSetupPhases are generally triggered from
	      the ABYParty class for the function call on ExecCircuit. Whenever a circuit is built
	      and executed these methods mentioned above are triggered. For instance, if the circuit
	      setup expects a execution and reset loop for n iterations, these methods would be
	      triggered n times. Also the precomputation phase plays a huge role in these methods.
	*/

	/**
	 Method for preparing the sharing setup.
	 \param 	setup 	Object for setting up the share.
	 */
	virtual void PrepareSetupPhase(ABYSetup* setup) = 0;
	/**
	 Method for performing the sharing setup.
	 \param 	setup 	Object for setting up the share.
	 */
	virtual void PerformSetupPhase(ABYSetup* setup) = 0;
	/**
	 Method for finishing the sharing setup.
	 \param 	setup 	Object for setting up the share.
	 */
	virtual void FinishSetupPhase(ABYSetup* setup) = 0;

	/**
	 Method for evaluating the local operations.
	 \param 	level 	_______________________
	 */
	virtual void EvaluateLocalOperations(uint32_t level) = 0;
	/**
	 Method for evaluating the interactive operations.
	 \param 	level 	_______________________
	 */
	virtual void EvaluateInteractiveOperations(uint32_t level) = 0;

	/**
	 Method for preparing the online phase <Better description please>
	 */
	virtual void PrepareOnlinePhase() = 0;

	/**
	 Method for finishing the circuit layer <Better description please>
	 */
	virtual void FinishCircuitLayer() = 0;

	/**
	 Method for sending the data.
	 \param 	sendbuf 	sender buffer
	 \param 	bytesize	data size
	 */
	virtual void GetDataToSend(std::vector<BYTE*>& sendbuf, std::vector<uint64_t>& bytesize) = 0;
	/**
	 Method for receiving the data.
	 \param 	rsvbuf 		receiver buffer
	 \param 	rcvsize		data size
	 */
	virtual void GetBuffersToReceive(std::vector<BYTE*>& rcvbuf, std::vector<uint64_t>& rcvbytes) = 0;
	/**
	 Method for Instantiating a gate
	 \param gate 		Input gate
	 */
	virtual void InstantiateGate(GATE* gate) = 0;
	/**
	 Method for finding the used gate with the gateid.
	 \param gateid		Id of the used gate.
	 */
	void UsedGate(uint32_t gateid);

	/**
	 Method for freeing gate memory depending on its type
	 \param gate		Pointer to the gat to free
	 */
	void FreeGate(GATE* gate);

	/**
	 Method for assigning the input
	 \param 	input 		Input
	 */
	virtual uint32_t AssignInput(CBitVector& input) = 0;
	/**
	 Method for getting the output
	 \param 	output 		Output
	 */
	virtual uint32_t GetOutput(CBitVector& out) = 0;
	/**
	 Method for finding the maximum communication rounds.
	 */
	virtual uint32_t GetMaxCommunicationRounds() = 0;
	/**
	 Method for finding the number of non-linear operations.
	 */
	virtual uint32_t GetNumNonLinearOperations() = 0;
	/**
	 Method for knowing the sharing type used.
	 */
	virtual const char* sharing_type() = 0;
	/**
	 Method for printing the performance statistics.
	 */
	virtual void PrintPerformanceStatistics() = 0;
	/**
	 Method for _________________________________
	 */
	virtual Circuit* GetCircuitBuildRoutine() = 0;


	/*Pre-computation Methods*/
	/*Note:
			The circuits are setup and executed into different phases: setup and online phases.
			In setup phase the implementation uses the baseOTs to compute OTs and use the OTs
			to communicate and compute the MTs. Online phase primarily deals with the rest of
			the circuit execution where the circuit evaluation is performed.
			Currently Precomputation scheme is only implemented for BoolSharing circuits or
	 	 	GMW based circuits. The implementation involves the use of 4 different modes of
	 	 	operation: PrecomputationStore, PrecomputationRead, PrecomputeInRAM and finally
	 	 	the default. In precomputationStore:  the MTs are computed for the specified
	 	 	circuit design and stored in a specific file(depending on the role) and the online
	 	 	phase of the circuit is skipped. In precomputationRead: the MTs are not computed
	 	 	again instead, read	from a specific file(depending on the role). Potentially, in
	 	 	this mode Setup phase is per-se skipped and focused on the online phase.
	 	 	In PrecomputeInRAM mode generally used with large iterations of circuits(similar to AES designs)
	 	 	we run the setup phase in the first iteration and use the result of the MTs in the
	 	 	following phases. Ideally such an implementation is not secure.
	*/
	/**
	 Method for Pre-computation phase.
	*/
	virtual void PreComputationPhase() = 0;

	/**
	 Setting precomputation phase value
	*/
	void SetPreCompPhaseValue(ePreCompPhase in_phase_value);

	/**
	 Getting precomputation phase value
	*/
	ePreCompPhase GetPreCompPhaseValue();
	/**
	Method to delete the File which stores the precomputation values.
	*/
	void PreCompFileDelete();


protected:
	/**
	 Method for evaluating Callback gate for the inputted
	 gate object.
	 \param gateid		Gate identifier
	 */
	void EvaluateCallbackGate(uint32_t gateid);
	/**
	 Method for evaluating an ASSERT gate that checks the plaintext value of
	 a gate to a specified reference.
	 \param gateid		Gate identifier
	 \param	circ_type	Is it a Boolean or Arithmetic share that is print
	 */
	void EvaluateAssertGate(uint32_t gateid, e_circuit circ_type);
	/**
	 Method for evaluating a PRINT_VAL gate that prints the plaintext
	 output of a gate.
	 \param gateid		Gate identifier
	 \param	circ_type	Is it a Boolean or Arithmetic share that is print
	 */
	void EvaluatePrintValGate(uint32_t gateid, e_circuit circ_type);
	/**
	 Method parsing the output of a gate into a standard format that can be
	 printed or compared to a reference.
	 \param gateid		Gate identifier
	 \param	circ_type	Is it a Boolean or Arithmetic share that is print
	 \param	bitlen		Returns the bit length of the output value

	 \returns	The value of the gate in a standardized format
	 */
	UGATE_T* ReadOutputValue(uint32_t gateid, e_circuit circ_type, uint32_t* bitlen);


	e_sharing m_eContext; /** Which sharing is executed */
	uint32_t m_nShareBitLen; /**< Bit length of shared item. */
	ABYCircuit* m_pCircuit; /**< Circuit pointer. */
	std::vector<GATE>& m_vGates; /**< Reference to vector of gates. */
	e_role m_eRole; /**< Role object. */
	crypto* m_cCrypto; /**< Class that contains cryptographic routines */
	uint32_t m_nSecParamBytes; /**< Number of security param bytes. */
	uint32_t m_nTypeBitLen; /** Bit-length of the arithmetic shares in arithsharing */
	uint64_t m_nFilePos;/**< Variable which stores the position of the file pointer. */
	ePreCompPhase m_ePhaseValue;/**< Variable storing the current Precomputation Mode */
	const std::string m_cCircuitFileDir; /** Storing path to .aby circuit files (e.g. floating point) */

};

#endif
