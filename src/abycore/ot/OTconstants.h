/**
 \file 		OTconstants.h
 \author	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2017 Engineering Cryptographic Protocols Group, TU Darmstadt
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
 \brief		File containing all OT constants used throughout the source.
 			IMPORTANT: Note that this is the ABY Version of the file that uses different defines than the base OTExtenstion version.
 */


#ifndef _OT_CONSTANTS_H_
#define _OT_CONSTANTS_H_

#include "../ENCRYPTO_utils/constants.h"

// IMPORTANT: Note that this is the ABY Version of this file that uses different #defines than the base OTExtenstion version.
#define ABY_OT

#define BATCH
#define VERIFY_OT
#define FIXED_KEY_AES_HASHING
//#define USE_PIPELINED_AES_NI
//#define SIMPLE_TRANSPOSE //activate the simple transpose, only required for benchmarking, not recommended

#define NUMOTBLOCKS 1024
#define BUFFER_OT_KEYS NUMOTBLOCKS


#define OT_ADMIN_CHANNEL MAX_NUM_COMM_CHANNELS-2
#define OT_BASE_CHANNEL 0

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

#endif /* _OT_CONSTANTS_H_ */
