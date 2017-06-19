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
	m_nNumOTThreads = numThreads;
	m_cCrypt = crypt;
	m_eRole = role;
	m_eMTGenAlg = mtalgo;

	if (!Init()) {
		cerr << "Error in ABYSetup init" << endl;
		exit(0);
	}
}

ABYSetup::~ABYSetup() {
	Cleanup();
}

BOOL ABYSetup::Init() {
//	uint32_t symbits = m_cCrypt->get_seclvl().symbits;
//	uint32_t aes_key_bytes = m_cCrypt->get_aes_key_bytes();

	m_vIKNPOTTasks.resize(2);
	m_vKKOTTasks.resize(2);

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
		//m_cDGKMTGen = new DGKParty(m_cCrypt->get_seclvl().ifcbits, sizeof(UINT16_T) * 8);
	}

	return true;
}

void ABYSetup::Cleanup() {
	for(size_t i = 0; i < m_vThreads.size(); i++) {
		m_vThreads[i]->PutJob(e_Stop);
		m_vThreads[i]->Wait();
		delete m_vThreads[i];
	}
	if(m_tSetupChan) {
		m_tSetupChan->synchronize_end();
		delete m_tSetupChan;
	}
	if(iknp_ot_sender) {
		delete iknp_ot_sender;
	}
	if(iknp_ot_receiver) {
		delete iknp_ot_receiver;
	}

#ifdef USE_KK_OT
	//FIXME: deleting kk_ot_receiver or sender causes a SegFault in AES with Yao
	if(kk_ot_receiver) {
		delete kk_ot_receiver;
	}
	if(kk_ot_sender) {
		delete kk_ot_sender;
	}
#endif

}

BOOL ABYSetup::PrepareSetupPhase(comm_ctx* comm) {
	m_tComm = comm;

	m_tSetupChan = new channel(ABY_SETUP_CHANNEL, m_tComm->rcv_std, m_tComm->snd_std);
	if(m_eRole == SERVER) {
		iknp_ot_sender = new IKNPOTExtSnd(m_cCrypt, m_tComm->rcv_std, m_tComm->snd_std);
		iknp_ot_receiver = new IKNPOTExtRec(m_cCrypt, m_tComm->rcv_inv, m_tComm->snd_inv);

#ifdef USE_KK_OT
		kk_ot_sender = new KKOTExtSnd(m_cCrypt, m_tComm->rcv_std, m_tComm->snd_std);
		kk_ot_receiver = new KKOTExtRec(m_cCrypt, m_tComm->rcv_inv, m_tComm->snd_inv);
#endif
	} else {
		iknp_ot_receiver = new IKNPOTExtRec(m_cCrypt, m_tComm->rcv_std, m_tComm->snd_std);
		iknp_ot_sender = new IKNPOTExtSnd(m_cCrypt,  m_tComm->rcv_inv, m_tComm->snd_inv);

#ifdef USE_KK_OT
		kk_ot_receiver = new KKOTExtRec(m_cCrypt, m_tComm->rcv_std, m_tComm->snd_std);
		kk_ot_sender = new KKOTExtSnd(m_cCrypt,  m_tComm->rcv_inv, m_tComm->snd_inv);
#endif
	}
	//Start Naor-Pinkas base OTs
	WakeupWorkerThreads(e_NP);
	BOOL success = WaitWorkerThreads();

	if (m_eMTGenAlg == MT_PAILLIER) {
		//Start Paillier key generation for the MT generation
		m_cPaillierMTGen->keyExchange(m_tSetupChan);
	}

	return success;
}

BOOL ABYSetup::PerformSetupPhase() {
	/* Compute OT extension */
	WakeupWorkerThreads(e_IKNPOTExt);
	BOOL success = WaitWorkerThreads();

#ifdef USE_KK_OT
	WakeupWorkerThreads(e_KKOTExt);
	success &= WaitWorkerThreads();
#endif

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
			m_cDGKMTGen[i]->keyExchange(m_tSetupChan);
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

BOOL ABYSetup::FinishSetupPhase() {
	//Do nothing atm
	return true;
}

BOOL ABYSetup::ThreadRunNPSnd(uint32_t exec) {
	BOOL success = true;
	iknp_ot_sender->ComputeBaseOTs(P_FIELD);
#ifdef USE_KK_OT
	kk_ot_sender->ComputeBaseOTs(P_FIELD);
#endif
	return success;
}

BOOL ABYSetup::ThreadRunNPRcv(uint32_t exec) {
	BOOL success = true;
	iknp_ot_receiver->ComputeBaseOTs(P_FIELD);
#ifdef USE_KK_OT
	kk_ot_receiver->ComputeBaseOTs(P_FIELD);
#endif
	return success;
}

//Receiver and Sender switch roles in the beginning of the OT extension protocol to obliviously transfer a matrix T
BOOL ABYSetup::ThreadRunIKNPSnd(uint32_t exec) {
	bool success = true;

	uint32_t inverse = exec ^ m_eRole;
	uint32_t nsndvals = 2;

	CBitVector** X = (CBitVector**) malloc(sizeof(CBitVector*) * nsndvals);
	for (uint32_t i = 0; i < m_vIKNPOTTasks[inverse].size(); i++) {
		IKNP_OTTask* task = m_vIKNPOTTasks[inverse][i]; //m_vOTTasks[inverse][0];
		uint32_t numOTs = task->numOTs;
		X[0] = (task->pval.sndval.X0);
		X[1] = (task->pval.sndval.X1);

#ifndef BATCH
		cout << "Starting OT sender routine for " << numOTs << " OTs on " << task->bitlen << " bit strings " << endl;
#endif
		success &= iknp_ot_sender->send(numOTs, task->bitlen, nsndvals, X, task->snd_flavor, task->rec_flavor, m_nNumOTThreads, task->mskfct);
#ifdef DEBUGSETUP
		cout << "OT sender results for bitlen = " << task->bitlen << ": " << endl;
		cout << "X0: ";
		task->pval.sndval.X0->PrintHex();
		cout << "X1: ";
		task->pval.sndval.X1->PrintHex();
#endif
		if(task->delete_mskfct)	{
			delete task->mskfct;
		}
		free(task);
	}
	m_vIKNPOTTasks[inverse].resize(0);
	free(X);
	return success;
}

BOOL ABYSetup::ThreadRunIKNPRcv(uint32_t exec) {
	bool success = true;

	uint32_t inverse = exec ^ m_eRole;
//	uint32_t symbits = m_cCrypt->get_seclvl().symbits;
	uint32_t nsndvals = 2;

	for (uint32_t i = 0; i < m_vIKNPOTTasks[inverse].size(); i++) {

		IKNP_OTTask* task = m_vIKNPOTTasks[inverse][i];
		uint32_t numOTs = task->numOTs;

#ifndef BATCH
		cout << "Starting OT receiver routine for " << numOTs << " OTs on " << task->bitlen << " bit strings " << endl;
#endif
		success = iknp_ot_receiver->receive(numOTs, task->bitlen, nsndvals, (task->pval.rcvval.C), (task->pval.rcvval.R), task->snd_flavor, task->rec_flavor, m_nNumOTThreads, task->mskfct);
#ifdef DEBUGSETUP
		cout << "OT receiver results for bitlen = " << task->bitlen << ": " << endl;
		cout << "C: ";
		task->pval.rcvval.C->PrintBinary();
		cout << "R: ";
		task->pval.rcvval.R->PrintHex();
#endif
		if(task->delete_mskfct)	{
			delete task->mskfct;
		}
		free(task);
	}
	m_vIKNPOTTasks[inverse].resize(0);
	return success;
}


//KK13 OT extension sender and receiver routine outsourced in separate threads
BOOL ABYSetup::ThreadRunKKSnd(uint32_t exec) {
	bool success = true;

	uint32_t inverse = exec ^ m_eRole;

	for (uint32_t i = 0; i < m_vKKOTTasks[inverse].size(); i++) {
		KK_OTTask* task = m_vKKOTTasks[inverse][i];

		uint32_t numOTs = task->numOTs;
		CBitVector** X = task->pval.sndval.X;

		/*cout << "Address of X = " << (uint64_t) X << endl;
		for(uint32_t j = 0; j < task->nsndvals; j++) {
			cout << (uint64_t) X[j] << endl;
		}*/


#ifndef BATCH
		cout << "Starting 1oo" << task->nsndvals << " KK OT sender routine for " << numOTs << " OTs on " << task->bitlen << " bit strings " << endl;
#endif
		success &= kk_ot_sender->send(numOTs, task->bitlen, task->nsndvals, X, task->snd_flavor, task->rec_flavor, m_nNumOTThreads, task->mskfct);
#ifdef DEBUGSETUP
		cout << "OT sender results for bitlen = " << task->bitlen << ": " << endl;
		for(uint32_t j = 0; j < task->nsndvals; j++) {
			cout << "X" << j << ": ";
			X[j]->PrintHex();
		}
#endif
		if(task->delete_mskfct)	{
			delete task->mskfct;
		}
		free(task);
	}
	m_vKKOTTasks[inverse].resize(0);
	return success;
}

BOOL ABYSetup::ThreadRunKKRcv(uint32_t exec) {
	bool success = true;

	uint32_t inverse = exec ^ m_eRole;
//	uint32_t symbits = m_cCrypt->get_seclvl().symbits;
//	uint32_t nsndvals = 2;

	for (uint32_t i = 0; i < m_vKKOTTasks[inverse].size(); i++) {

		KK_OTTask* task = m_vKKOTTasks[inverse][i];
		uint32_t numOTs = task->numOTs;

#ifndef BATCH
		cout << "Starting 1oo" << task->nsndvals << " KK OT receiver routine for " << numOTs << " OTs on " << task->bitlen << " bit strings " << endl;
#endif
		success = kk_ot_receiver->receive(numOTs, task->bitlen, task->nsndvals, (task->pval.rcvval.C), (task->pval.rcvval.R), task->snd_flavor, task->rec_flavor, m_nNumOTThreads, task->mskfct);
#ifdef DEBUGSETUP
		cout << "OT receiver results for bitlen = " << task->bitlen << ": " << endl;
		cout << "C: ";
		task->pval.rcvval.C->PrintBinary();
		cout << "R: ";
		task->pval.rcvval.R->PrintHex();
#endif
		if(task->delete_mskfct)	{
			delete task->mskfct;
		}
		free(task);
	}
	m_vKKOTTasks[inverse].resize(0);
	return success;
}


BOOL ABYSetup::ThreadRunPaillierMTGen(uint32_t threadid) {

	uint32_t nthreads = 2 * m_nNumOTThreads;

	channel* djnchan = new channel(DJN_CHANNEL+threadid, m_tComm->rcv_std, m_tComm->snd_std);
	for (uint32_t i = 0; i < m_vPKMTGenTasks.size(); i++) {

		PKMTGenVals* ptask = m_vPKMTGenTasks[i];

		uint32_t nummtsperthread = ceil_divide(ptask->numMTs, nthreads);

		uint32_t mynummts = nummtsperthread; //times two since we need the number of MTs to be a multiple of 2 internally
		uint32_t sharebytelen = ceil_divide(ptask->sharebitlen, 8);
		if (threadid == nthreads - 1) {
			mynummts = ptask->numMTs - (nthreads-1 ) * nummtsperthread;
		}

		uint32_t mystartpos = nummtsperthread * threadid * sharebytelen;
		m_cPaillierMTGen->setSharelLength(ptask->sharebitlen);

		UINT32_T roleoffset = mystartpos + sharebytelen * (mynummts / 2);
		if (m_eRole == SERVER) {
			m_cPaillierMTGen->preCompBench(ptask->A->GetArr() + mystartpos, ptask->B->GetArr() + mystartpos, ptask->C->GetArr() + mystartpos, ptask->A->GetArr() + roleoffset,
					ptask->B->GetArr() + roleoffset, ptask->C->GetArr() + roleoffset, mynummts, djnchan);
		} else {
			m_cPaillierMTGen->preCompBench(ptask->A->GetArr() + roleoffset, ptask->B->GetArr() + roleoffset, ptask->C->GetArr() + roleoffset, ptask->A->GetArr() + mystartpos,
					ptask->B->GetArr() + mystartpos, ptask->C->GetArr() + mystartpos, mynummts, djnchan);
		}
		free(ptask);
	}
	djnchan->synchronize_end();
	delete djnchan;

	return true;
}

BOOL ABYSetup::ThreadRunDGKMTGen(uint32_t threadid) {

	uint32_t nthreads = 2 * m_nNumOTThreads;

	channel* dgkchan = new channel(DGK_CHANNEL+threadid, m_tComm->rcv_std, m_tComm->snd_std);

	for (uint32_t i = 0; i < m_vPKMTGenTasks.size(); i++) {
		PKMTGenVals* ptask = m_vPKMTGenTasks[i];

		//times two since we need the number of MTs to be a multiple of 2 internally
		uint32_t nummtsperthread = ceil_divide(ptask->numMTs, nthreads);
		uint32_t mynummts = nummtsperthread;
		uint32_t sharebytelen = ceil_divide(ptask->sharebitlen, 8);

		//if the number of MTs is not evenly divisible among all threads
		if (threadid == nthreads - 1) {
			mynummts = ptask->numMTs - (nthreads-1 ) * nummtsperthread;
		}

		uint32_t mystartpos = nummtsperthread * threadid * sharebytelen;

		//add an offset depending on the role of the party
		UINT32_T roleoffset = mystartpos + sharebytelen * (mynummts / 2);

		if (m_eRole == SERVER) {
			m_cDGKMTGen[i]->preCompBench(ptask->A->GetArr() + mystartpos, ptask->B->GetArr() + mystartpos, ptask->C->GetArr() + mystartpos, ptask->A->GetArr() + roleoffset,
					ptask->B->GetArr() + roleoffset, ptask->C->GetArr() + roleoffset, mynummts, dgkchan);
		} else {
			m_cDGKMTGen[i]->preCompBench(ptask->A->GetArr() + roleoffset, ptask->B->GetArr() + roleoffset, ptask->C->GetArr() + roleoffset, ptask->A->GetArr() + mystartpos,
					ptask->B->GetArr() + mystartpos, ptask->C->GetArr() + mystartpos, mynummts, dgkchan);
		}
		free(ptask);
	}
	dgkchan->synchronize_end();
	delete dgkchan;

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
	m_tSetupChan->send(m_tsndtask.sndbuf, m_tsndtask.sndbytes);
	return true;
}

BOOL ABYSetup::ThreadReceiveData(uint32_t threadid) {
	 m_tSetupChan->blocking_receive(m_trcvtask.rcvbuf, m_trcvtask.rcvbytes);
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
		case e_IKNPOTExt:
			if (threadid == SERVER)
				bSuccess = m_pCallback->ThreadRunIKNPSnd(threadid);
			else
				bSuccess = m_pCallback->ThreadRunIKNPRcv(threadid);
			break;
		case e_KKOTExt:
			if (threadid == SERVER)
				bSuccess = m_pCallback->ThreadRunKKSnd(threadid);
			else
				bSuccess = m_pCallback->ThreadRunKKRcv(threadid);
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
		case e_Transmit:
		case e_Undefined:
		default:
			cerr << "Error: Undefined / unimplemented OT Job!" << endl;
		}
		m_pCallback->ThreadNotifyTaskDone(bSuccess);
	}
}

void ABYSetup::Reset() {
	/* Clear any remaining OT tasks */
	for (uint32_t i = 0; i < m_vIKNPOTTasks.size(); i++) {
		m_vIKNPOTTasks[i].clear();
	}
	/* Clear any remaining OT tasks */
	for (uint32_t i = 0; i < m_vKKOTTasks.size(); i++) {
		m_vKKOTTasks[i].clear();
	}
}
