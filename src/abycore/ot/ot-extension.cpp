/**
 \file 		ot-extension.cpp
 \author 	michael.zohner@ec-spride.de
 \copyright __________________
 \brief		Methods for the OT Extension routine
 */

#include "ot-extension.h"

BOOL OTExtensionReceiver::receive(uint32_t numOTs, uint32_t bitlength, CBitVector& choices, CBitVector& ret, BYTE type, uint32_t numThreads, MaskingFunction* unmaskfct) {
	m_nOTs = numOTs;
	m_nBitLength = bitlength;
	m_nChoices = choices;
	m_nRet = ret;
	m_bProtocol = type;
	m_fMaskFct = unmaskfct;
	return receive(numThreads);
}
;

//Initialize and start numThreads OTSenderThread
BOOL OTExtensionReceiver::receive(uint32_t numThreads) {
	if (m_nOTs == 0)
		return true;

	//The total number of OTs that is performed has to be a multiple of numThreads*Z_REGISTER_BITS
	uint32_t wd_size_bits = 1 << (ceil_log2(m_nBaseOTs));
	uint32_t internal_numOTs = ceil_divide(PadToMultiple(m_nOTs, wd_size_bits), numThreads);

	//Create temporary result buf to which the threads write their temporary masks
	m_vTempOTMasks.Create(internal_numOTs * numThreads * m_nBitLength);

	vector<OTReceiverThread*> rThreads(numThreads);
	for (uint32_t i = 0; i < numThreads; i++) {
		rThreads[i] = new OTReceiverThread(i, internal_numOTs, this);
		rThreads[i]->Start();
	}

	ReceiveAndProcess(numThreads);

	for (uint32_t i = 0; i < numThreads; i++) {
		rThreads[i]->Wait();
	}

	m_nCounter += m_nOTs;

	for (uint32_t i = 0; i < numThreads; i++)
		delete rThreads[i];

	if (m_bProtocol == R_OT) {
		m_nRet.Copy(m_vTempOTMasks.GetArr(), 0, ceil_divide(m_nOTs * m_nBitLength, 8));
		m_vTempOTMasks.delCBitVector();
	}

#ifdef VERIFY_OT
	//Wait for the signal of the corresponding sender thread
	BYTE finished = 0x01;
	m_vSockets[0].Send(&finished, 1);
	verifyOT(m_nOTs);
#endif

	return true;
}

BOOL OTExtensionReceiver::OTReceiverRoutine(uint32_t id, uint32_t myNumOTs) {
	uint32_t myStartPos = id * myNumOTs;
	uint32_t i = myStartPos, nProgress = myStartPos;
	uint32_t RoundWindow = 2;
	uint32_t roundctr = 0;
	uint32_t wd_size_bits = 1 << (ceil_log2(m_nBaseOTs));

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	uint32_t lim = myStartPos + myNumOTs;

	uint32_t processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(myNumOTs, wd_size_bits));
	uint32_t OTsPerIteration = processedOTBlocks * wd_size_bits;
	uint32_t OTwindow = NUMOTBLOCKS * wd_size_bits * RoundWindow;
	CSocket sock = m_vSockets[id];

	//counter variables
	uint32_t numblocks = ceil_divide(myNumOTs, OTsPerIteration);
	uint32_t nSize;

	// The receive buffer
	CBitVector vRcv;
	if (m_bProtocol == G_OT)
		vRcv.Create(OTsPerIteration * m_nBitLength * m_nSndVals);
	else if (m_bProtocol == C_OT)	// || m_bProtocol == S_OT)
		vRcv.Create(OTsPerIteration * m_nBitLength);

	// A temporary part of the T matrix
	CBitVector T(wd_size_bits * OTsPerIteration);

	// The send buffer
	CBitVector vSnd(m_nBaseOTs * OTsPerIteration);

	// A temporary buffer that stores the resulting seeds from the hash buffer
	//TODO: Check for some maximum size
	CBitVector seedbuf(OTwindow * m_cCrypt->get_aes_key_bytes() * 8);

	BYTE ctr_buf[AES_BYTES] = { 0 };
	uint32_t* counter = (uint32_t*) ctr_buf;
	(*counter) = myStartPos + m_nCounter;

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0, totalChkTime = 0;
	timeval tempStart, tempEnd;
#endif

	while (i < lim) {
		processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(lim - i, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;
		nSize = ceil_divide(m_nBaseOTs * OTsPerIteration, 8);

#ifdef OTTiming
		gettimeofday(&tempStart, NULL);
#endif
		BuildMatrices(T, vSnd, processedOTBlocks, i, ctr_buf);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalMtxTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		T.EklundhBitTranspose(wd_size_bits, OTsPerIteration);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalTnsTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		HashValues(T, seedbuf, i, min(lim - i, OTsPerIteration));
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalHshTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		sock.Send(vSnd.GetArr(), nSize);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalSndTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		(*counter) += min(lim - i, OTsPerIteration);
		i += min(lim - i, OTsPerIteration);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalRcvTime += getMillies(tempStart, tempEnd);
#endif

		vSnd.Reset();
		T.Reset();
	}

	T.delCBitVector();
	vSnd.delCBitVector();
	vRcv.delCBitVector();
	seedbuf.delCBitVector();

#ifdef OTTiming
	cout << "Receiver time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << endl;
	cout << "Time needed for: " << endl;
	cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << endl;
	cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << endl;
	cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << endl;
	cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << endl;
	cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << endl;
#endif
#ifndef BATCH
	cout << "Receiver finished successfully" << endl;
#endif
	//sleep(1);
	return TRUE;
}

void OTExtensionReceiver::BuildMatrices(CBitVector& T, CBitVector& SndBuf, uint32_t numblocks, uint32_t ctr, BYTE* ctr_buf) {
	uint32_t* counter = (uint32_t*) ctr_buf;
	uint32_t tempctr = (*counter);
	uint32_t wd_size_bytes = 1 << (ceil_log2(m_nBaseOTs) - 3);
	uint32_t rowbytelen = wd_size_bytes * numblocks;
	uint32_t iters = rowbytelen / AES_BYTES;

	BYTE* Tptr = T.GetArr();
	BYTE* sndbufptr = SndBuf.GetArr();
	BYTE* choiceptr;

	AES_KEY_CTX* seedptr = m_vKeySeedMtx;

	for (uint32_t k = 0; k < m_nBaseOTs; k++) {
		for (uint32_t b = 0; b < iters; b++, (*counter)++) {
			m_cCrypt->encrypt(seedptr + 2 * k, Tptr, ctr_buf, AES_BYTES);
#ifdef DEBUG_MALICIOUS
			cout << "correct: Tka = " << k << ": " << (hex) << ((uint64_t*) Tptr)[0] << ((uint64_t*) Tptr)[1] << (hex) << endl;
#endif
			Tptr += AES_BYTES;

			m_cCrypt->encrypt(seedptr + (2 * k) + 1, sndbufptr, ctr_buf, AES_BYTES);
#ifdef DEBUG_MALICIOUS
			cout << "correct: Tkb = " << k << ": " << (hex) << ((uint64_t*) sndbufptr)[0] << ((uint64_t*) sndbufptr)[1] << (hex) << endl;
#endif
			sndbufptr += AES_BYTES;
		}
		(*counter) = tempctr;
	}

	choiceptr = m_nChoices.GetArr() + ceil_divide(ctr, 8);
	for (uint32_t k = 0; k < m_nBaseOTs; k++) {
		SndBuf.XORBytesReverse(choiceptr, k * rowbytelen, rowbytelen);
	}

	SndBuf.XORBytes(T.GetArr(), 0, rowbytelen * m_nBaseOTs);
}

void OTExtensionReceiver::HashValues(CBitVector& T, CBitVector& seedbuf, uint32_t ctr, uint32_t processedOTs) {
	BYTE* Tptr = T.GetArr();
	BYTE* bufptr = seedbuf.GetArr();

	BYTE hash_buf[m_cCrypt->get_hash_bytes()];

	uint32_t wd_size_bytes = (1 << ((ceil_log2(m_nBaseOTs)) - 3));
	uint32_t hashinbytelen = ceil_divide(m_nBaseOTs, 8);
	uint32_t aes_key_bytes = m_cCrypt->get_aes_key_bytes();

	for (uint64_t i = (uint64_t) ctr; i < ctr + processedOTs; i++, Tptr += wd_size_bytes, bufptr += aes_key_bytes) {
#ifdef OT_HASH_DEBUG
		cout << "Hash-In for i = " << i << ": " << (hex);
		for(uint32_t p = 0; p < hashinbytelen; p++)
		cout << (uint32_t) Tptr[p];
		cout << (dec) << endl;
#endif

#ifdef FIXED_KEY_AES_HASHING
		FixedKeyHashing(m_kCRFKey, bufptr, Tptr, hash_buf, i, ceil_divide(m_nBaseOTs, 8), m_cCrypt);
#else
		m_cCrypt->hash_ctr(bufptr, AES_KEY_BYTES, Tptr, ceil_divide(m_nBaseOTs, 8), i);
#endif

	}

#ifndef HIGH_SPEED_ROT_LT
	m_fMaskFct->expandMask(m_vTempOTMasks, seedbuf.GetArr(), ctr, processedOTs, m_nBitLength, m_cCrypt);
#endif
}

//void OTExtensionReceiver::ReceiveAndProcess(CBitVector& vRcv, CBitVector& seedbuf, int id, int ctr, int processedOTs)
void OTExtensionReceiver::ReceiveAndProcess(uint32_t numThreads) {
	uint32_t progress = 0;
	uint32_t wd_size_bits = 1 << (ceil_log2(m_nBaseOTs));
	uint32_t threadOTs = ceil_divide(PadToMultiple(m_nOTs, wd_size_bits), numThreads);
	uint32_t processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(threadOTs, wd_size_bits));
	uint32_t OTsPerIteration = processedOTBlocks * wd_size_bits;
	uint32_t processedOTs;
	uint32_t otid;
	uint32_t rcvbytes;
	CBitVector vRcv;
	uint32_t csockid = 0;

#ifdef OTTiming
	double totalUnmaskTime = 0, totalCheckTime = 0;
	timeval tempStart, tempEnd;
#endif

	if (m_bProtocol == G_OT)
		vRcv.Create(OTsPerIteration * m_nBitLength * m_nSndVals);
	else if (m_bProtocol == C_OT)
		vRcv.Create(OTsPerIteration * m_nBitLength);
	else if (m_bProtocol == R_OT)
		return;

	while (progress < m_nOTs) {
		m_vSockets[csockid].Receive((BYTE*) &otid, sizeof(uint32_t));
		m_vSockets[csockid].Receive((BYTE*) &processedOTs, sizeof(uint32_t));
#ifdef OTTiming
		gettimeofday(&tempStart, NULL);
#endif
		if (m_bProtocol == G_OT || m_bProtocol == C_OT) {
			rcvbytes = ceil_divide(processedOTs * m_nBitLength, 8);
			if (m_bProtocol == G_OT)
				rcvbytes = rcvbytes * m_nSndVals;
			rcvbytes = m_vSockets[csockid].Receive(vRcv.GetArr(), rcvbytes);

			m_fMaskFct->UnMask(otid, processedOTs, m_nChoices, m_nRet, vRcv, m_vTempOTMasks, m_bProtocol);
#ifdef OTTiming
			gettimeofday(&tempEnd, NULL);
			totalUnmaskTime += getMillies(tempStart, tempEnd);
#endif
		}
		progress += processedOTs;
	}

#ifdef OTTiming
	cout << "Total time spent processing received data: " << totalUnmaskTime << " ms" << endl;
#endif

	vRcv.delCBitVector();
}

BOOL OTExtensionReceiver::verifyOT(uint32_t NumOTs) {
	CSocket sock = m_vSockets[0];
	CBitVector vRcvX0(NUMOTBLOCKS * AES_BITS * m_nBitLength);
	CBitVector vRcvX1(NUMOTBLOCKS * AES_BITS * m_nBitLength);
	CBitVector* Xc;
	uint32_t processedOTBlocks, OTsPerIteration;
	uint32_t bytelen = ceil_divide(m_nBitLength, 8);
	BYTE* tempXc = (BYTE*) malloc(bytelen);
	BYTE* tempRet = (BYTE*) malloc(bytelen);
	BYTE resp;
	for (uint32_t i = 0; i < NumOTs;) {
		processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(NumOTs - i, AES_BITS));
		OTsPerIteration = min(processedOTBlocks * AES_BITS, NumOTs - i);
		sock.Receive(vRcvX0.GetArr(), ceil_divide(m_nBitLength * OTsPerIteration, 8));
		sock.Receive(vRcvX1.GetArr(), ceil_divide(m_nBitLength * OTsPerIteration, 8));
		for (uint32_t j = 0; j < OTsPerIteration && i < NumOTs; j++, i++) {
			if (m_nChoices.GetBitNoMask(i) == 0)
				Xc = &vRcvX0;
			else
				Xc = &vRcvX1;

			Xc->GetBits(tempXc, j * m_nBitLength, m_nBitLength);
			m_nRet.GetBits(tempRet, i * m_nBitLength, m_nBitLength);
			for (uint32_t k = 0; k < bytelen; k++) {
				if (tempXc[k] != tempRet[k]) {
					cout << "Error at position i = " << i << ", k = " << k << ", with X" << (hex) << (uint32_t) m_nChoices.GetBitNoMask(i) << " = " << (uint32_t) tempXc[k]
							<< " and res = " << (uint32_t) tempRet[k] << (dec) << endl;
					resp = 0x00;
					sock.Send(&resp, 1);
					return false;
				}
			}
		}
		resp = 0x01;
		sock.Send(&resp, 1);
	}
	free(tempXc);
	free(tempRet);

	vRcvX0.delCBitVector();
	vRcvX1.delCBitVector();

	cout << "OT Verification successful" << endl;
	return true;
}

BOOL OTExtensionSender::send(uint32_t numOTs, uint32_t bitlength, CBitVector& x0, CBitVector& x1, BYTE type, uint32_t numThreads, MaskingFunction* maskfct) {
	m_nOTs = numOTs;
	m_nBitLength = bitlength;
	m_vValues[0] = x0;
	m_vValues[1] = x1;
	m_bProtocol = type;
	m_fMaskFct = maskfct;
	return send(numThreads);
}

//Initialize and start numThreads OTSenderThread
BOOL OTExtensionSender::send(uint32_t numThreads) {
	if (m_nOTs == 0)
		return true;

	//The total number of OTs that is performed has to be a multiple of numThreads*Z_REGISTER_BITS
	uint32_t wd_size_bits = 1 << (ceil_log2(m_nBaseOTs));
	uint32_t numOTs = ceil_divide(PadToMultiple(m_nOTs, wd_size_bits), numThreads);
	m_nBlocks = 0;
	m_lSendLock = new CLock;

	vector<OTSenderThread*> sThreads(numThreads);

	for (uint32_t i = 0; i < numThreads; i++) {
		sThreads[i] = new OTSenderThread(i, numOTs, this);
		sThreads[i]->Start();
	}

	SendBlocks(numThreads);

	for (uint32_t i = 0; i < numThreads; i++) {
		sThreads[i]->Wait();
	}

	m_nCounter += m_nOTs;

	for (uint32_t i = 0; i < numThreads; i++) {
		delete sThreads[i];
	}

#ifdef VERIFY_OT
	BYTE finished;
	m_vSockets[0].Receive(&finished, 1);

	verifyOT(m_nOTs);
#endif
	return true;
}

//BOOL OTsender(int nSndVals, int nOTs, int startpos, CSocket& sock, CBitVector& U, AES_KEY* vKeySeeds, CBitVector* values, BYTE* seed)
BOOL OTExtensionSender::OTSenderRoutine(uint32_t id, uint32_t myNumOTs) {
	CSocket sock = m_vSockets[id];

	uint32_t nProgress;
	uint32_t myStartPos = id * myNumOTs;
	uint32_t wd_size_bits = 1 << (ceil_log2(m_nBaseOTs));
	uint32_t processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(myNumOTs, wd_size_bits));
	uint32_t OTsPerIteration = processedOTBlocks * wd_size_bits;

	myNumOTs = min(myNumOTs + myStartPos, m_nOTs) - myStartPos;
	uint32_t lim = myStartPos + myNumOTs;

	// The vector with the received bits
	CBitVector vRcv(m_nBaseOTs * OTsPerIteration);

	// Holds the reply that is sent back to the receiver
	uint32_t numsndvals = 2;
	CBitVector* vSnd;

	CBitVector* seedbuf = new CBitVector[m_nSndVals];
	for (uint32_t u = 0; u < m_nSndVals; u++)
		seedbuf[u].Create(OTsPerIteration * m_cCrypt->get_aes_key_bytes() * 8);
#ifdef ZDEBUG
	cout << "seedbuf size = " <<OTsPerIteration * AES_KEY_BITS << endl;
#endif
	vSnd = new CBitVector[numsndvals];	//(CBitVector*) malloc(sizeof(CBitVector) * numsndvals);
	for (uint32_t i = 0; i < numsndvals; i++) {
		vSnd[i].Create(OTsPerIteration * m_nBitLength);
	}

	// Contains the parts of the V matrix
	CBitVector Q(wd_size_bits * OTsPerIteration);

	// A buffer that holds a counting value, required for a faster interaction with the AES calls
	BYTE ctr_buf[AES_BYTES];
	memset(ctr_buf, 0, AES_BYTES);
	uint32_t* counter = (uint32_t*) ctr_buf;
	counter[0] = myStartPos + m_nCounter;

	nProgress = myStartPos;

#ifdef OTTiming
	double totalMtxTime = 0, totalTnsTime = 0, totalHshTime = 0, totalRcvTime = 0, totalSndTime = 0;
	timeval tempStart, tempEnd;
#endif

	while (nProgress < lim) //do while there are still transfers missing
	{
		processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(lim - nProgress, wd_size_bits));
		OTsPerIteration = processedOTBlocks * wd_size_bits;

#ifdef ZDEBUG
		cout << "Processing block " << nProgress << " with length: " << OTsPerIteration << ", and limit: " << lim << endl;
#endif

#ifdef OTTiming
		gettimeofday(&tempStart, NULL);
#endif
		sock.Receive(vRcv.GetArr(), ceil_divide(m_nBaseOTs * OTsPerIteration, 8));
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalRcvTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		BuildQMatrix(Q, vRcv, processedOTBlocks, ctr_buf);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalMtxTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		Q.EklundhBitTranspose(wd_size_bits, OTsPerIteration);
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalTnsTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		MaskInputs(Q, seedbuf, vSnd, nProgress, min(lim - nProgress, OTsPerIteration));
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalHshTime += getMillies(tempStart, tempEnd);
		gettimeofday(&tempStart, NULL);
#endif
		ProcessAndEnqueue(vSnd, id, nProgress, min(lim - nProgress, OTsPerIteration));
#ifdef OTTiming
		gettimeofday(&tempEnd, NULL);
		totalSndTime += getMillies(tempStart, tempEnd);
#endif
		(*counter) += min(lim - nProgress, OTsPerIteration);
		nProgress += min(lim - nProgress, OTsPerIteration);
		Q.Reset();
	}

	vRcv.delCBitVector();
	Q.delCBitVector();
	for (uint32_t u = 0; u < m_nSndVals; u++)
		seedbuf[u].delCBitVector();

	for (uint32_t i = 0; i < numsndvals; i++)
		vSnd[i].delCBitVector();
	if (numsndvals > 0)
		free(vSnd);

#ifdef OTTiming
	cout << "Sender time benchmark for performing " << myNumOTs << " OTs on " << m_nBitLength << " bit strings" << endl;
	cout << "Time needed for: " << endl;
	cout << "\t Matrix Generation:\t" << totalMtxTime << " ms" << endl;
	cout << "\t Sending Matrix:\t" << totalSndTime << " ms" << endl;
	cout << "\t Transposing Matrix:\t" << totalTnsTime << " ms" << endl;
	cout << "\t Hashing Matrix:\t" << totalHshTime << " ms" << endl;
	cout << "\t Receiving Values:\t" << totalRcvTime << " ms" << endl;
#endif

#ifndef BATCH
	cout << "Sender finished successfully" << endl;
#endif
	return TRUE;
}

void OTExtensionSender::BuildQMatrix(CBitVector& T, CBitVector& RcvBuf, uint32_t numblocks, BYTE* ctr_buf) {
	BYTE* rcvbufptr = RcvBuf.GetArr();
	BYTE* Tptr = T.GetArr();
	uint32_t dummy;
	uint32_t* counter = (uint32_t*) ctr_buf;
	uint32_t tempctr = *counter;
	uint32_t wd_size_bytes = 1 << (ceil_log2(m_nBaseOTs) - 3);
	uint32_t rowbytelen = wd_size_bytes * numblocks;

	AES_KEY_CTX* seedptr = m_vKeySeeds;
	uint32_t otid = (*counter) - m_nCounter;

	uint32_t iters = rowbytelen / AES_BYTES;
	for (uint32_t k = 0, b; k < m_nBaseOTs; k++, rcvbufptr += rowbytelen) {
		for (b = 0; b < iters; b++, (*counter)++, Tptr += AES_BYTES) {
			m_cCrypt->encrypt(seedptr + k, Tptr, ctr_buf, AES_BYTES);
#ifdef DEBUG_MALICIOUS
			cout << "k = " << k << ": "<< (hex) << ((uint64_t*) Tptr)[0] << ((uint64_t*) Tptr)[1] << (hex) << endl;
#endif

		}
		*counter = tempctr;
	}

	//XOR m_nU on top
	rcvbufptr = RcvBuf.GetArr();
	for (uint32_t k = 0; k < m_nBaseOTs; k++, rcvbufptr += rowbytelen) {
		if (m_vU.GetBit(k)) {
			T.XORBytes(rcvbufptr, k * rowbytelen, rowbytelen);
		}
	}
}

void OTExtensionSender::MaskInputs(CBitVector& Q, CBitVector* seedbuf, CBitVector* snd_buf, uint32_t ctr, uint32_t processedOTs) {
	uint32_t numhashiters = ceil_divide(m_nBitLength, m_cCrypt->get_hash_bytes());
	uint32_t hashinbytelen = ceil_divide(m_nBaseOTs, 8);
	uint32_t wd_size_bytes = 1 << (ceil_log2(m_nBaseOTs) - 3);
	uint32_t u;
	uint32_t aes_key_bytes = m_cCrypt->get_aes_key_bytes();
#ifndef FIXED_KEY_AES_HASHING
	HASH_CTX sha, shatmp;
#endif

	BYTE hash_buf[m_cCrypt->get_hash_bytes()];
	uint64_t* Qptr = (uint64_t*) Q.GetArr();
	uint64_t* Uptr = (uint64_t*) m_vU.GetArr();

	BYTE** sbp = new BYTE*[m_nSndVals];

	for (u = 0; u < m_nSndVals; u++)
		sbp[u] = seedbuf[u].GetArr();

	for (uint64_t i = (uint64_t) ctr, j = 0; j < processedOTs; i++, j++, Qptr += 2) {

#ifndef FIXED_KEY_AES_HASHING
		MPC_HASH_INIT(&sha);
		MPC_HASH_UPDATE(&sha, (BYTE*) &i, sizeof(i));

		shatmp = sha;
#endif
		for (u = 0; u < m_nSndVals; u++) {

#ifdef HIGH_SPEED_ROT_LT
			if(u == 1) {
				Qptr[0]^=Uptr[0];
				Qptr[1]^=Uptr[1];
			}
#else
			if (u == 1)
				Q.XORBytes((uint8_t*) Uptr, j * wd_size_bytes, hashinbytelen);
#endif

#ifdef OT_HASH_DEBUG
			cout << "Hash-In for i = " << i << ", u = " << u << ": " << (hex);
			for(uint32_t p = 0; p < hashinbytelen; p++)
			cout << (uint32_t) (Q.GetArr() + j * wd_size_bytes)[p];
			cout << (dec) << endl;
#endif

#ifdef FIXED_KEY_AES_HASHING
			FixedKeyHashing(m_kCRFKey, sbp[u], (BYTE*) Qptr, hash_buf, i, hashinbytelen, m_cCrypt);
#else
			sha = shatmp;

			MPC_HASH_UPDATE(&sha, Q.GetArr()+ j * wd_size_bytes, hashinbytelen);
			MPC_HASH_FINAL(&sha, hash_buf);

			memcpy(sbp[u], hash_buf, AES_KEY_BYTES);
#endif
			sbp[u] += aes_key_bytes;

		}
	}

#ifndef HIGH_SPEED_ROT_LT
	//Two calls to expandMask, both writing into snd_buf
	for (uint32_t u = 0; u < m_nSndVals; u++)
		m_fMaskFct->expandMask(snd_buf[u], seedbuf[u].GetArr(), 0, processedOTs, m_nBitLength, m_cCrypt);
#endif
}

void OTExtensionSender::ProcessAndEnqueue(CBitVector* snd_buf, uint32_t id, uint32_t progress, uint32_t processedOTs) {
	m_fMaskFct->Mask(progress, processedOTs, m_vValues, snd_buf, m_bProtocol);

	if (m_bProtocol == R_OT)
		return;

	OTBlock* block = new OTBlock;
	uint32_t bufsize = ceil_divide(processedOTs * m_nBitLength, 8);

	block->blockid = progress;
	block->processedOTs = processedOTs;

	if (m_bProtocol == G_OT) {
		block->snd_buf = new BYTE[bufsize << 1];
		memcpy(block->snd_buf, snd_buf[0].GetArr(), bufsize);
		memcpy(block->snd_buf + bufsize, snd_buf[1].GetArr(), bufsize);
	} else if (m_bProtocol == C_OT) {
		block->snd_buf = new BYTE[bufsize];
		memcpy(block->snd_buf, snd_buf[1].GetArr(), bufsize);
	}

	m_lSendLock->Lock();
	//Lock this part if multiple threads are used!
	if (m_nBlocks == 0) {
		m_sBlockHead = block;
		m_sBlockTail = block;
	} else {
		m_sBlockTail->next = block;
		m_sBlockTail = block;
	}
	m_nBlocks++;
	m_lSendLock->Unlock();
}

void OTExtensionSender::SendBlocks(uint32_t numThreads) {
	OTBlock* tempBlock;
	uint32_t progress = 0;
	uint32_t csockid = 0;
	if (m_bProtocol == R_OT)
		return;

#ifdef OTTiming
	double totalTnsTime = 0;
	timeval tempStart, tempEnd;
#endif

	while (progress < m_nOTs) {
		if (m_nBlocks > 0) {
#ifdef OTTiming
			gettimeofday(&tempStart, NULL);
#endif
			tempBlock = m_sBlockHead;
			//send: blockid, #processedOTs, threadid, #checks, permbits
			m_vSockets[csockid].Send((BYTE*) &(tempBlock->blockid), sizeof(uint32_t));
			m_vSockets[csockid].Send((BYTE*) &(tempBlock->processedOTs), sizeof(uint32_t));

			if (m_bProtocol == G_OT) {
				m_vSockets[csockid].Send(tempBlock->snd_buf, 2 * ceil_divide((tempBlock->processedOTs) * m_nBitLength, 8));
			} else if (m_bProtocol == C_OT) {
				m_vSockets[csockid].Send(tempBlock->snd_buf, ceil_divide((tempBlock->processedOTs) * m_nBitLength, 8));
			}
			//Lock this part
			m_sBlockHead = m_sBlockHead->next;

			m_lSendLock->Lock();
			m_nBlocks--;
			m_lSendLock->Unlock();

			progress += tempBlock->processedOTs;
			if (m_bProtocol != R_OT)
				delete tempBlock->snd_buf;

			delete tempBlock;

#ifdef OTTiming
			gettimeofday(&tempEnd, NULL);
			totalTnsTime += getMillies(tempStart, tempEnd);
#endif
		}
	}
#ifdef OTTiming
	cout << "Total time spent transmitting data: " << totalTnsTime << endl;
#endif
}

BOOL OTExtensionSender::verifyOT(uint32_t NumOTs) {
	CSocket sock = m_vSockets[0];
	CBitVector vSnd(NUMOTBLOCKS * AES_BITS * m_nBitLength);
	uint32_t processedOTBlocks, OTsPerIteration;
	uint32_t bytelen = ceil_divide(m_nBitLength, 8);
	uint32_t nSnd;
	BYTE resp;
	for (uint32_t i = 0; i < NumOTs; i += OTsPerIteration) {
		processedOTBlocks = min((uint32_t) NUMOTBLOCKS, ceil_divide(NumOTs - i, AES_BITS));
		OTsPerIteration = min(processedOTBlocks * AES_BITS, NumOTs - i);
		nSnd = ceil_divide(OTsPerIteration * m_nBitLength, 8);
		vSnd.Copy(m_vValues[0].GetArr() + ceil_divide(i * m_nBitLength, 8), 0, nSnd);
		sock.Send(vSnd.GetArr(), nSnd);
		vSnd.Copy(m_vValues[1].GetArr() + ceil_divide(i * m_nBitLength, 8), 0, nSnd);
		sock.Send(vSnd.GetArr(), nSnd);
		sock.Receive(&resp, 1);
		if (resp == 0x00) {
			cout << "OT verification unsuccessful" << endl;
			return false;
		}
	}
	vSnd.delCBitVector();
	cout << "OT Verification successful" << endl;
	return true;
}
