/**
 \file 		typedefs.h
 \author 	michael.zohner@ec-spride.de
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
 \brief		Typedefs Implementation
 */

#ifndef __TYPEDEFS_H__
#define __TYPEDEFS_H__

#include <sys/time.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define BATCH
//#define ZDEBUG
//#define PRINT_PERFORMANCE_STATS
#define USE_MULTI_MUX_GATES //TODO Multimux gates lead to errors, fix!
//#define SIMPLE_TRANSPOSE //activate the simple transpose in OT, only required for debugging
//#define VERIFY_OT


#define MAXGATES 32000000

#ifndef BATCH
//#define PRINT_OUTPUT
#endif

#define two_pow(e) (((uint64_t) 1) << (e))

typedef struct SECURITYLEVELS {
	int statbits;
	int symbits;
	int ifcbits;
	int eccpfbits;
	int ecckcbits;
} seclvl;

typedef int BOOL;
typedef long LONG;

typedef unsigned char BYTE;
typedef unsigned short USHORT;
typedef unsigned int UINT;
typedef unsigned long ULONG;
typedef BYTE UINT8_T;
typedef USHORT UINT16_T;
typedef UINT UINT32_T;
typedef unsigned long long UINT64_T;
typedef long long SINT64_T;

typedef ULONG DWORD;
typedef UINT64_T UGATE_T;
typedef UINT64_T REGISTER_SIZE;

#define GATE_T_BITS (sizeof(UGATE_T) * 8)

typedef REGISTER_SIZE REGSIZE;
#define LOG2_REGISTER_SIZE		ceil_log2(sizeof(REGISTER_SIZE) << 3)

#define FILL_BYTES				AES_BYTES
#define FILL_BITS				AES_BITS

#define OT_WINDOW_SIZE		(AES_BITS*4)
#define OT_WINDOW_SIZE_BYTES	(AES_BYTES*4)

#define MAX_REPLY_BITS			65536 //at most 2^16 bits may be sent in one go

#define RETRY_CONNECT		1000
#define CONNECT_TIMEO_MILISEC	10000

#define SNDVALS 2

#define OTEXT_BLOCK_SIZE_BITS	AES_BITS
#define OTEXT_BLOCK_SIZE_BYTES	AES_BYTES

#define VECTOR_INTERNAL_SIZE 8

#define			SERVER_ID	0
#define			CLIENT_ID	1

#define MAX_INT (~0)
#if (MAX_INT == 0xFFFFFFFF)
#define MACHINE_SIZE_32
#elif (MAX_INT == 0xFFFFFFFFFFFFFFFF)
#define MACHINE_SIZE_64
#else
#define MACHINE_SIZE_16
#endif

template<class T>
T rem(T a, T b) {
	return ((a) > 0) ? (a) % (b) : (a) % (b) + ((b) > 0 ? (b) : (b) * -1);
}
template<class T>
T sub(T a, T b, T m) {
	return ((b) > (a)) ? (a) + (m) - (b) : (a) - (b);
}


#ifndef FALSE
#define FALSE			0
#endif
#ifndef TRUE
#define TRUE			1
#endif
#define ZERO_BYTE		0
#define MAX_BYTE		0xFF
#define MAX_UINT		0xFFFFFFFF

#ifdef WIN32
#include <WinSock2.h>
#include <windows.h>

typedef unsigned short USHORT;
typedef int socklen_t;
#pragma comment(lib, "wsock32.lib")

#define SleepMiliSec(x)			Sleep(x)

#else //WIN32

#include <sys/types.h>       
#include <sys/socket.h>      
#include <netdb.h>           
#include <arpa/inet.h>       
#include <unistd.h>          
#include <netinet/in.h>   
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <queue>
#include <float.h>


typedef int SOCKET;
#define INVALID_SOCKET -1

#define SleepMiliSec(x)			usleep((x)<<10)
#endif// WIN32

#define ceil_divide(x, y)			(( ((x) + (y)-1)/(y)))
#define bits_in_bytes(bits) (ceil_divide((bits), 8))
#define pad_to_multiple(x, y) 		( ceil_divide(x, y) * (y))


#define PadToRegisterSize(x) 		(PadToMultiple(x, OTEXT_BLOCK_SIZE_BITS))
#define PadToMultiple(x, y) 		( ceil_divide(x, y) * (y))

#include <cstring>
#include <string>  
#include <vector> 
#include <iostream>

using namespace std;


//TODO: this is bad, fix occurrences of ceil_log2 and replace by ceil_log2_min1 where log(1) = 1 is necessary. For all else use ceil_log2_real
static uint32_t ceil_log2(int bits) {
	if (bits == 1)
		return 1;
	int targetlevel = 0, bitstemp = bits;
	while (bitstemp >>= 1)
		++targetlevel;
	return targetlevel + ((1 << targetlevel) < bits);
}

static uint32_t ceil_log2_min1(int bits) {
	if (bits <= 1)
		return 1;
	int targetlevel = 0, bitstemp = bits;
	while (bitstemp >>= 1)
		++targetlevel;
	return targetlevel + ((1 << targetlevel) < bits);
}

static uint32_t ceil_log2_real(int bits) {
	if (bits == 1)
		return 0;
	int targetlevel = 0, bitstemp = bits;
	while (bitstemp >>= 1)
		++targetlevel;
	return targetlevel + ((1 << targetlevel) < bits);
}

static uint32_t floor_log2(int bits) {
	if (bits == 1)
		return 1;
	int targetlevel = 0;
	while (bits >>= 1)
		++targetlevel;
	return targetlevel;
}

#define pad_to_power_of_two(e) ( ((uint64_t) 1) << (ceil_log2(e)) )


/*compute (a-b) mod (m+1) as: b > a ? (m) - (b-1) + a : a - b	*/
#define MOD_SUB(a, b, m) (( ((b) > (a))? (m) - ((b) -1 ) + a : a - b))

#endif //__TYPEDEFS_H__

