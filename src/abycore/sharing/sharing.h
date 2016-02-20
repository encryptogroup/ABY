/**
 \file 		sharing.h
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
 \brief		Sharing class.
 A virtual class that contains the methods which the sharing
 schemes have to implement
 */

#ifndef __SHARING_H__
#define __SHARING_H__

//#include "../circuit/circuit.h"
#include "../circuit/abycircuit.h"
#include "../circuit/circuit.h"
#include "../util/cbitvector.h"
#include "../aby/abysetup.h"
#include "../util/constants.h"
#include "../util/crypto/crypto.h"
#include <assert.h>
//#define DEBUGSHARING

/**
 \def MAXSHAREBUFSIZE
 \brief Maximum size of share buffer.
 */
#define MAXSHAREBUFSIZE 1000000

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
	Sharing(e_role role, uint32_t sharebitlen, ABYCircuit* circuit, crypto* crypt) {
		m_nShareBitLen = sharebitlen;
		m_pCircuit = circuit;
		m_pGates = m_pCircuit->Gates();
		m_eRole = role;
		m_cCrypto = crypt;
		m_nSecParamBytes = ceil_divide(m_cCrypto->get_seclvl().symbits, 8);
	}
	;
	/**
	 Destructor of class.
	 */
	~Sharing() {
	}
	;

	/**	Reset method */
	virtual void Reset() = 0;

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
	virtual void FinishCircuitLayer(uint32_t level) = 0;

	/**	
	 Method for sending the data.
	 \param 	sendbuf 	sender buffer
	 \param 	bytesize	data size
	 */
	virtual void GetDataToSend(vector<BYTE*>& sendbuf, vector<uint64_t>& bytesize) = 0;
	/**	
	 Method for receiving the data.
	 \param 	rsvbuf 		receiver buffer
	 \param 	rcvsize		data size
	 */
	virtual void GetBuffersToReceive(vector<BYTE*>& rcvbuf, vector<uint64_t>& rcvbytes) = 0;
	/**	
	 Method for Instantiating a gate
	 \param gate 		Input gate
	 */
	virtual void InstantiateGate(GATE* gate) = 0;
	/**	
	 Method for finding the used gate with the gateid.
	 \param gateid		Id of the used gate.
	 */
	virtual void UsedGate(uint32_t gateid) = 0;

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

protected:
	/**
	 Method for evaluating Callback gate for the inputted
	 gate object.
	 \param gateid		Gate identifier
	 */
	void EvaluateCallbackGate(uint32_t gateid);

	uint32_t m_nShareBitLen; /**< Bit length of shared item. */
	GATE* m_pGates; /**< Pointer to array of Logical Gates. */
	ABYCircuit* m_pCircuit; /**< Circuit pointer. */
	e_role m_eRole; /**< Role object. */
	uint32_t m_nSecParamBytes; /**< Number of security param bytes. */
	crypto* m_cCrypto; /**< Class that contains cryptographic routines */
};

#endif
