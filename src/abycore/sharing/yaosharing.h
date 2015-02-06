/**
 \file 		yaosharing.h
 \author	michael.zohner@ec-spride.de
 \copyright	________________
 \brief		Yao Sharing class.
 */

#ifndef __YAOSHARING_H__
#define __YAOSHARING_H__

#include "sharing.h"
#include "../util/yaokey.h"
#include "../circuit/booleancircuits.h"
#include "../util/constants.h"

#define FIXED_KEY_GARBLING
//#define MAXSHAREBUFSIZE 1000000

//TODO the garbled table is addressed as uint32_t and might overflow if sufficient (>4mio AND gates) are required. Change to LONG

//TODO use this to implement a pipelined style transmission later on

/** 
 \def 	GARBLED_TABLE_WINDOW 
 \brief	____________________
 */
#define GARBLED_TABLE_WINDOW 100000000
/** 
 \def 	KEYS_PER_GATE_IN_TABLE 
 \brief	____________________
 */
#define KEYS_PER_GATE_IN_TABLE 2

/**
 Yao Sharing class. <Detailed Description please.>
 */
class YaoSharing: public Sharing {

public:

	/** Constructor for the class. */
	YaoSharing(e_role role, uint32_t sharebitlen, ABYCircuit* circuit, crypto* crypt) :
			Sharing(role, sharebitlen, circuit, crypt) {
		Init();
	}
	;
	/** Destructor for the class. */
	~YaoSharing() {
	}
	;

	// METHODS FROM SUPER CLASS SHARING...
	virtual void Reset() = 0;
	virtual void PrepareSetupPhase(ABYSetup* setup) = 0;
	virtual void PerformSetupPhase(ABYSetup* setup) = 0;
	virtual void FinishSetupPhase(ABYSetup* setup) = 0;
	virtual void EvaluateLocalOperations(uint32_t gateid) = 0;

	virtual void FinishCircuitLayer() = 0;

	virtual void PrepareOnlinePhase() = 0;

	virtual void InstantiateGate(GATE* gate) = 0;
	virtual void UsedGate(uint32_t gateid) = 0;

	virtual void GetDataToSend(vector<BYTE*>& sendbuf, vector<uint32_t>& bytesize) = 0;
	virtual void GetBuffersToReceive(vector<BYTE*>& rcvbuf, vector<uint32_t>& rcvbytes) = 0;

	virtual uint32_t AssignInput(CBitVector& input) = 0;
	virtual uint32_t GetOutput(CBitVector& out) = 0;

	uint32_t GetMaxCommunicationRounds() {
		return m_cBoolCircuit->GetMaxDepth();
	}
	;
	uint32_t GetNumNonLinearOperations() {
		return m_nANDGates;
	}
	;

	Circuit* GetCircuitBuildRoutine() {
		return m_cBoolCircuit;
	}
	;

	void PrintPerformanceStatistics();
	//SUPER CLASS METHODS END HERE...

	/** 
	 Evaluating SIMD Gate.
	 \param 	gateid 	Identifier of the gate to be evaluated.
	 */
	void EvaluateSIMDGate(uint32_t gateid);

protected:
	/* A variable that points to inline functions for key xor */
	YaoKey *m_pKeyOps; /**< A variable that points to inline functions for key xor.*/
	uint32_t m_nANDGates; /**< AND Gates_____________*/
	uint32_t m_nXORGates; /**< XOR Gates_____________*/

	XORMasking *fMaskFct; /**< Mask ____________*/
	vector<GATE*> m_vANDGates; /**< Vector of AND Gates. */

	vector<GATE*> m_vOutputShareGates; /**< Vector of output share gates. */

	uint32_t m_nInputShareSndSize; /**< Input share send size. */
	uint32_t m_nOutputShareSndSize; /**< Output share send size. */

	uint32_t m_nInputShareRcvSize; /**< Input share receiver size. */
	uint32_t m_nOutputShareRcvSize; /**< Output share receiver size. */

	uint32_t m_nClientInputBits; /**< Client Input Bits. */
	CBitVector m_vClientInputKeys; /**< Client Input Keys. */

	uint32_t m_nConversionInputBits; /**< Conversion Input Bits. */
	//CBitVector			m_vConversionInputKeys;

	uint32_t m_nServerInputBits; /**< Server Input Bits. */
	CBitVector m_vServerInputKeys; /**< Server Input Keys. */

	CBitVector m_vGarbledCircuit; /**< Garbled Circuit Vector.*/
	uint64_t m_nGarbledTableCtr; /**< Garbled Table Counter. */

	BYTE* m_bZeroBuf; /**< Zero Buffer. */
	BYTE* m_bTempKeyBuf; /**< Temporary Key Buffer. */

	BooleanCircuit* m_cBoolCircuit; /**< Boolean circuit */

	uint32_t m_nSecParamIters; /**< Secure_____________*/

#ifdef FIXED_KEY_GARBLING
	BYTE* m_bResKeyBuf; /**< _________________________*/
	AES_KEY_CTX* m_kGarble; /**< _________________________*/
#endif

	/** Initiator function. This method is invoked from the constructor of the class.*/
	void Init();

	/**	
	 Encrypt Wire Function <DETAILED DESCRIPTION> 
	 \param  c 		________________
	 \param  p 		________________
	 \param  id 		________________	
	 */
	BOOL EncryptWire(BYTE* c, BYTE* p, uint32_t id);

	/** Print the key. */
	void PrintKey(BYTE* key);
};

#endif /* __YAOSHARING_H__ */
