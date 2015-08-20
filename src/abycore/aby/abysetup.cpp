/**
 \file 		abysetup.cpp
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
 \brief		ABYSetup class implementation.
 */

#include "abysetup.h"

ABYSetup::ABYSetup(crypto* crypt, uint32_t numThreads, e_role role, e_mt_gen_alg mtalgo) {
	//m_sSecLvl = seclvl;
	m_nNumOTThreads = numThreads;
	//m_aSeed = seed;
	m_cCrypt = crypt;
	m_eRole = role;
	m_nSndVals = 2;
	m_nIKNPProgress = 0;
	m_eMTGenAlg = mtalgo;

	if (!Init()) {
		cerr << "Error in ABYSetup init" << endl;
		exit(0);
	}
}

BOOL ABYSetup::Init() {
	//Initialize the NaorPinkas Base OT with the security level and seed

	uint32_t symbits = m_cCrypt->get_seclvl().symbits;
	uint32_t aes_key_bytes = m_cCrypt->get_aes_key_bytes();
	np = new NaorPinkas(m_cCrypt, P_FIELD); //m_sSecLvl, m_aSeed);

	//m_vU.Create(symbits);

	m_vKeySeedMtx = (BYTE*) malloc(symbits * m_nSndVals * aes_key_bytes);
	m_vKeySeeds = (BYTE*) malloc(symbits * aes_key_bytes);

	m_vOTTasks.resize(2);

	uint32_t threadsize = 2 * m_nNumOTThreads;
	m_vThreads.resize(threadsize);
	for (uint32_t i = 0; i < threadsize; i++) { //double the number of threads for role-flippling
		m_vThreads[i] = new CWorkerThread(i, this);
		m_vThreads[i]->Start();
	}

	//the bit length of the DJN and DGK party is irrelevant here, since it is set for each MT Gen task independently
	if (m_eMTGenAlg == MT_PAILLIER) {
#ifndef BATCH
		cout << "Creating new DJNPart with key bitlen = " << m_cCrypt->get_seclvl().ifcbits << endl;
#endif
		m_cPaillierMTGen = new DJNParty(m_cCrypt->get_seclvl().ifcbits, sizeof(UINT16_T) * 8);
	} else if (m_eMTGenAlg == MT_DGK) {
#ifndef BATCH
		cout << "Creating new DGKPart with key bitlen = " << m_cCrypt->get_seclvl().ifcbits << endl;
#endif
#ifdef BENCH_PRECOMP
		m_cDGKMTGen = (DGKParty**) malloc(sizeof(DGKParty*));
		m_cDGKMTGen[0] = new DGKParty(m_sSecLvl.ifcbits, sizeof(UINT64_T) * 8, 0);
#endif
		//m_cDGKMTGen = new DGKParty(m_sSecLvl.ifcbits, sizeof(UINT16_T) * 8);
	}

	return true;
}

void ABYSetup::Cleanup() {

	//m_vU.delCBitVector();

	//np->Cleanup();
	delete np;


	//delete ot_sender;
	//delete ot_receiver;

	//delete m_cPaillierMTGen;

	delete ot_sender;
	delete ot_receiver;

	free(m_vKeySeedMtx);
	free(m_vKeySeeds);
}

BOOL ABYSetup::PrepareSetupPhase(vector<CSocket>& sockets) {
	m_vSockets = sockets;
	//Start Naor-Pinkas base OTs
	WakeupWorkerThreads(e_NP);
	BOOL success = WaitWorkerThreads();

	if (m_eMTGenAlg == MT_PAILLIER) {
		//Start Paillier key generation for the MT generation
		m_cPaillierMTGen->keyExchange(m_vSockets[0]);
	}
	//OTExtSnd sender(m_nSndVals, m_cCrypt, sockptr, m_vU, m_vKeySeeds);
	CSocket* sockptr = m_vSockets.data() + ((m_eRole!=SERVER) * m_nNumOTThreads);
	ot_sender = new OTExtSnd(m_nSndVals, m_cCrypt, sockptr, m_vU, m_vKeySeeds);
	sockptr = m_vSockets.data() + ((m_eRole!=CLIENT) * m_nNumOTThreads);
	ot_receiver = new OTExtRec(m_nSndVals, m_cCrypt, sockptr, m_vKeySeedMtx);

	m_vU.delCBitVector();
	return success;
}

BOOL ABYSetup::PerformSetupPhase(vector<CSocket>& sockets) {
	/* Compute OT extension */
	WakeupWorkerThreads(e_OTExt);
	BOOL success = WaitWorkerThreads();

	if (m_eMTGenAlg == MT_PAILLIER) {
		//Start Paillier MT generation
		WakeupWorkerThreads(e_MTPaillier);
		success &= WaitWorkerThreads();
	} else if (m_eMTGenAlg == MT_DGK) {
#ifndef BENCH_PRECOMP
		m_cDGKMTGen = (DGKParty**) malloc(sizeof(DGKParty*) * m_vPKMTGenTasks.size());
#endif
		for (uint32_t i = 0; i < m_vPKMTGenTasks.size(); i++) {
#ifndef BENCH_PRECOMP
			m_cDGKMTGen[i] = new DGKParty(m_cCrypt->get_seclvl().ifcbits, m_vPKMTGenTasks[i]->sharebitlen, 1);
#endif
			m_cDGKMTGen[i]->keyExchange(sockets[0]);
		}
		//Start DGK MT generation
		WakeupWorkerThreads(e_MTDGK);
		success &= WaitWorkerThreads();

		for (uint32_t i = 0; i < m_vPKMTGenTasks.size(); i++) {
			delete m_cDGKMTGen[i];
		}
		free(m_cDGKMTGen);
	}
	return success;
}

BOOL ABYSetup::ThreadRunNPSnd(uint32_t exec) {
	CSocket& sock = m_vSockets[exec ^ m_eRole];
	uint32_t symbits = m_cCrypt->get_seclvl().symbits;
	uint32_t hash_bytes = m_cCrypt->get_hash_bytes();
	uint32_t aes_key_bytes = m_cCrypt->get_aes_key_bytes();
	BYTE* pBuf = new BYTE[symbits * hash_bytes];
	BOOL success;
	m_vU.Create(symbits, m_cCrypt);		//, m_aSeed, cnt);
	//m_cCrypt->gen_rnd(m_vU.GetArr(), ceil_divide(symbits, 8));

	np->Receiver(m_nSndVals, symbits, m_vU, sock, pBuf);

	//Copy necessary key bits to keyseeds
	BYTE* pBufIdx = pBuf;
	for (uint32_t i = 0; i < symbits; i++) {
		memcpy(m_vKeySeeds + i * aes_key_bytes, pBufIdx, aes_key_bytes);
		pBufIdx += hash_bytes;
	}

	delete[] pBuf;
	return success;
}

BOOL ABYSetup::ThreadRunNPRcv(uint32_t exec) {
	// Execute NP receiver routine and obtain the key
	CSocket& sock = m_vSockets[exec ^ m_eRole];
	uint32_t symbits = m_cCrypt->get_seclvl().symbits;
	uint32_t hash_bytes = m_cCrypt->get_hash_bytes();
	uint32_t aes_key_bytes = m_cCrypt->get_aes_key_bytes();

	BYTE* pBuf = new BYTE[hash_bytes * symbits * m_nSndVals];
	BOOL success;

	np->Sender(m_nSndVals, symbits, sock, pBuf);

	//Copy necessary bits to keyseedmtx
	BYTE* pBufIdx = pBuf;
	for (uint32_t i = 0; i < symbits * m_nSndVals; i++) //320 times init after Naor Pinkas
			{
		memcpy(m_vKeySeedMtx + i * aes_key_bytes, pBufIdx, aes_key_bytes);
		pBufIdx += hash_bytes;
	}

	delete[] pBuf;

	return success;
}

//Receiver and Sender switch roles in the beginning of the OT extension protocol to obliviously transfer a matrix T
BOOL ABYSetup::ThreadRunIKNPSnd(uint32_t exec) {
	bool success = true;

	uint32_t inverse = exec ^ m_eRole;
	uint32_t symbits = m_cCrypt->get_seclvl().symbits;
	for (uint32_t i = 0; i < m_vOTTasks[inverse].size(); i++) {

		CSocket* sockptr = m_vSockets.data() + (inverse * m_nNumOTThreads);

		//OTExtSnd sender(m_nSndVals, m_cCrypt, sockptr, m_vU, m_vKeySeeds);

		OTTask* task = m_vOTTasks[inverse][i]; //m_vOTTasks[inverse][0];
		uint32_t numOTs = task->numOTs;

#ifndef BATCH
		cout << "Starting OT sender routine for " << numOTs << " OTs" << endl;
#endif
		success &= ot_sender->send(numOTs, task->bitlen, *(task->pval.sndval.X0), *(task->pval.sndval.X1), task->ottype, m_nNumOTThreads, task->mskfct);
#ifdef DEBUGSETUP
		cout << "OT sender results for bitlen = " << task->bitlen << ": " << endl;
		cout << "X0: ";
		task->pval.sndval.X0->PrintHex();
		cout << "X1: ";
		task->pval.sndval.X1->PrintHex();
#endif
	}
	m_vOTTasks[inverse].resize(0);

	return success;
}

BOOL ABYSetup::ThreadRunIKNPRcv(uint32_t exec) {
	bool success = true;

	uint32_t inverse = exec ^ m_eRole;
	uint32_t symbits = m_cCrypt->get_seclvl().symbits;
	for (uint32_t i = 0; i < m_vOTTasks[inverse].size(); i++) {

		OTTask* task = m_vOTTasks[inverse][i];
		CSocket* sockptr = m_vSockets.data() + (inverse * m_nNumOTThreads);

		//OTExtRec receiver(m_nSndVals, m_cCrypt, sockptr, m_vKeySeedMtx);

		uint32_t numOTs = task->numOTs;

#ifndef BATCH
		cout << "Starting OT receiver routine for " << numOTs << " OTs" << endl;
#endif
		success &= ot_receiver->receive(numOTs, task->bitlen, *(task->pval.rcvval.C), *(task->pval.rcvval.R), task->ottype, m_nNumOTThreads, task->mskfct);
#ifdef DEBUGSETUP
		cout << "OT receiver results for bitlen = " << task->bitlen << ": " << endl;
		cout << "C: ";
		task->pval.rcvval.C->PrintBinary();
		cout << "R: ";
		task->pval.rcvval.R->PrintHex();
#endif
	}
	m_vOTTasks[inverse].resize(0);

	return success;
}

BOOL ABYSetup::ThreadRunPaillierMTGen(uint32_t threadid) {

	uint32_t nthreads = 2 * m_nNumOTThreads;
	for (uint32_t i = 0; i < m_vPKMTGenTasks.size(); i++) {

		PKMTGenVals* ptask = m_vPKMTGenTasks[i];

		//TODO: adapt this to be more fine-granular. also, might cause problems
		uint32_t nummtsperthread = ceil_divide(ptask->numMTs, 2*nthreads) * 2;
		uint32_t mynummts = nummtsperthread; //times two since we need the number of MTs to be a multiple of 2 internally
		uint32_t sharebytelen = ceil_divide(ptask->sharebitlen, 8);
		if (threadid == nthreads - 1) {
			mynummts = mynummts - ((mynummts * nthreads) - ptask->numMTs);
		}

		uint32_t mystartpos = nummtsperthread * threadid * sharebytelen;
		m_cPaillierMTGen->setSharelLength(ptask->sharebitlen);

		UINT32_T roleoffset = mystartpos + sharebytelen * (mynummts / 2);

		if (m_eRole == SERVER) {
			m_cPaillierMTGen->preCompBench(ptask->A->GetArr() + mystartpos, ptask->B->GetArr() + mystartpos, ptask->C->GetArr() + mystartpos, ptask->A->GetArr() + roleoffset,
					ptask->B->GetArr() + roleoffset, ptask->C->GetArr() + roleoffset, mynummts, m_vSockets[threadid]);
		} else {
			m_cPaillierMTGen->preCompBench(ptask->A->GetArr() + roleoffset, ptask->B->GetArr() + roleoffset, ptask->C->GetArr() + roleoffset, ptask->A->GetArr() + mystartpos,
					ptask->B->GetArr() + mystartpos, ptask->C->GetArr() + mystartpos, mynummts, m_vSockets[threadid]);
		}

		//free(ptask);//TODO should be done by main task after the Paillier MT generation has been done
	}
	return true;
}

BOOL ABYSetup::ThreadRunDGKMTGen(uint32_t threadid) {

	uint32_t nthreads = 2 * m_nNumOTThreads;

	for (uint32_t i = 0; i < m_vPKMTGenTasks.size(); i++) {
		PKMTGenVals* ptask = m_vPKMTGenTasks[i];

		cout << "Number of share-bits: " << ptask->sharebitlen << endl;
		//times two since we need the number of MTs to be a multiple of 2 internally
		uint32_t nummtsperthread = ceil_divide(ptask->numMTs, 2*nthreads) * 2;
		uint32_t mynummts = nummtsperthread;
		uint32_t sharebytelen = ceil_divide(ptask->sharebitlen, 8);

		//if the number of MTs is not evenly divisible among all threads
		if (threadid == nthreads - 1) {
			mynummts = mynummts - ((mynummts * nthreads) - ptask->numMTs);
		}

		uint32_t mystartpos = nummtsperthread * threadid * sharebytelen;

		//add an offset depending on the role of the party
		UINT32_T roleoffset = mystartpos + sharebytelen * (mynummts / 2);

		if (m_eRole == SERVER) {
			m_cDGKMTGen[i]->preCompBench(ptask->A->GetArr() + mystartpos, ptask->B->GetArr() + mystartpos, ptask->C->GetArr() + mystartpos, ptask->A->GetArr() + roleoffset,
					ptask->B->GetArr() + roleoffset, ptask->C->GetArr() + roleoffset, mynummts, m_vSockets[threadid]);
		} else {
			m_cDGKMTGen[i]->preCompBench(ptask->A->GetArr() + roleoffset, ptask->B->GetArr() + roleoffset, ptask->C->GetArr() + roleoffset, ptask->A->GetArr() + mystartpos,
					ptask->B->GetArr() + mystartpos, ptask->C->GetArr() + mystartpos, mynummts, m_vSockets[threadid]);
		}
		//free(ptask);//TODO should be done by main task after the Paillier MT generation has been done
	}

	return true;
}

//starts a new sending thread but may stop if there is a thread already running
void ABYSetup::AddSendTask(BYTE* sndbuf, uint64_t sndbytes) {
	WaitWorkerThreads();
	m_tsndtask.sndbytes = sndbytes;
	m_tsndtask.sndbuf = sndbuf;
	WakeupWorkerThreads(e_Send);
}

BOOL ABYSetup::WaitForTransmissionEnd() {
	return WaitWorkerThreads();
}

//starts a new receivingthread but may stop if there is a thread already running
void ABYSetup::AddReceiveTask(BYTE* rcvbuf, uint64_t rcvbytes) {
	WaitWorkerThreads();
	m_trcvtask.rcvbytes = rcvbytes;
	m_trcvtask.rcvbuf = rcvbuf;
	WakeupWorkerThreads(e_Receive);
}

BOOL ABYSetup::ThreadSendData(uint32_t threadid) {
	m_vSockets[threadid].Send(m_tsndtask.sndbuf, m_tsndtask.sndbytes);
	return true;
}

BOOL ABYSetup::ThreadReceiveData(uint32_t threadid) {
	m_vSockets[threadid].Receive(m_trcvtask.rcvbuf, m_trcvtask.rcvbytes);
	return true;
}

//===========================================================================
// Thread Management
BOOL ABYSetup::WakeupWorkerThreads(EJobType e) {
	m_bWorkerThreadSuccess = TRUE;

	m_nWorkingThreads = 2;

	if (e == e_MTPaillier || e == e_MTDGK)
		m_nWorkingThreads = 2 * m_nNumOTThreads;
	else if (e == e_Send || e == e_Receive)
		m_nWorkingThreads = 1;

	uint32_t n = m_nWorkingThreads;

	for (uint32_t i = 0; i < n; i++)
		m_vThreads[i]->PutJob(e);

	return TRUE;
}

BOOL ABYSetup::WaitWorkerThreads() {
	if (!m_nWorkingThreads)
		return TRUE;

	for (;;) {
		m_lock.Lock();
		uint32_t n = m_nWorkingThreads;
		m_lock.Unlock();
		if (!n)
			return m_bWorkerThreadSuccess;
		m_evt.Wait();
	}
	return m_bWorkerThreadSuccess;
}

BOOL ABYSetup::ThreadNotifyTaskDone(BOOL bSuccess) {
	m_lock.Lock();
	uint32_t n = --m_nWorkingThreads;
	if (!bSuccess){
		m_bWorkerThreadSuccess = FALSE;
	}
	m_lock.Unlock();

	if (!n)
		m_evt.Set();
	return TRUE;
}

void ABYSetup::CWorkerThread::ThreadMain() {
	BOOL bSuccess = FALSE;
	for (;;) {
		m_evt.Wait();

		switch (m_eJob) {
		case e_Stop:
			return;
		case e_OTExt:
			if (threadid == SERVER)
				bSuccess = m_pCallback->ThreadRunIKNPSnd(threadid);
			else
				bSuccess = m_pCallback->ThreadRunIKNPRcv(threadid);
			break;
		case e_NP:
			if (threadid == SERVER)
				bSuccess = m_pCallback->ThreadRunNPSnd(threadid);
			else
				bSuccess = m_pCallback->ThreadRunNPRcv(threadid);
			break;
		case e_MTPaillier:
			bSuccess = m_pCallback->ThreadRunPaillierMTGen(threadid);
			break;
		case e_MTDGK:
			bSuccess = m_pCallback->ThreadRunDGKMTGen(threadid);
			break;
		case e_Send:
			bSuccess = m_pCallback->ThreadSendData(threadid);
			break;
		case e_Receive:
			bSuccess = m_pCallback->ThreadReceiveData(threadid);
			break;
		}
		m_pCallback->ThreadNotifyTaskDone(bSuccess);
	}
}

void ABYSetup::Reset() {
	/* Clear any remaining OT tasks */
	for (uint32_t i = 0; i < m_vOTTasks.size(); i++) {
		m_vOTTasks[i].clear();
	}
}

