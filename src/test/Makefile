#Makefile for ABY tests

#DO NOT MODIFY THIS FILE, unless you know what you're doing

#You should not need to call this makefile separately. It will me called from the Makefile in the root directory

#relative project folders
BIN = ../../bin
SRC = ..
CORE=${SRC}/abycore

SOURCES := $(shell find . -type f -name '*.cpp')
OBJECTS := $(patsubst %.cpp, %.o, ${SOURCES})

# object files for the test cases
OBJECTS_MILLIONAIRE_CIRC=${SRC}/examples/millionaire_prob/common/millionaire_prob.o
OBJECTS_AES_CIRC=${SRC}/examples/aes/common/aescircuit.o
OBJECTS_SHA1_CIRC=${SRC}/examples/sha1/common/sha1_circuit.o
OBJECTS_PSI_CIRC=${SRC}/examples/psi_scs/common/*.o
OBJECTS_PHASING_CIRC=${SRC}/examples/psi_phasing/common/*.o
OBJECTS_HASHING_CIRC=${SRC}/examples/psi_phasing/common/hashing/*.o
OBJECTS_LOWMC_CIRC=${SRC}/examples/lowmc/common/lowmccircuit.o

# directory for the Miracl library
MIRACL_LIB_DIR=${CORE}/util/miracl_lib
OBJECTS_MIRACL=${MIRACL_LIB_DIR}/*.o

# all source files and corresponding object files in abycore
SOURCES_CORE := $(shell find ${CORE} -type f -name '*.cpp' -not -path '*/util/Miracl/*' -not -path '*/ot/external/*')
OBJECTS_CORE := $(SOURCES_CORE:.cpp=.o)

# compiler settings
CC=g++

#Most aggressive optimizations, asserts are ignored
#COMPILER_OPTIONS=-O3 -DNDEBUG
#Optimizations
COMPILER_OPTIONS=-O2 -march=native
#DEBUG
#COMPILER_OPTIONS=-g3 -ggdb -O0# -Wall -Wextra

BATCH=
ARCHITECTURE = $(shell uname -m)
ifeq (${ARCHITECTURE},x86_64)
GNU_LIB_PATH:=x86_64
else
GNU_LIB_PATH:=i386
endif

#Include for Arch, Manjaro and the like
#INCLUDE=-I.. -I/usr/include/glib-2.0/ -I/usr/lib${ARCH_LIB_PATH}/glib-2.0/include

#Include for Debian, Ubuntu, Mint and the like
#INCLUDE=-I.. -I/usr/include/glib-2.0/ -I/usr/lib/${GNU_LIB_PATH}-linux-gnu/glib-2.0/include


CFLAGS=
LIBRARIES=-lgmp -lgmpxx -lpthread ${CORE}/util/miracl_lib/miracl.a -L /usr/lib  -lssl -lcrypto -lrt

#name fixed to test-aby
EXAMPLE = test-aby


all: ${BIN}/${EXAMPLE}.exe

${BIN}/${EXAMPLE}.exe: ${OBJECTS_CORE} ${OBJECTS} ${OBJECTS_MILLIONAIRE_CIRC} ${OBJECTS_AES_CIRC} ${OBJECTS_SHA1_CIRC} ${OBJECTS_LOWMC_CIRC} ${OBJECTS_PSI_CIRC} ${OBJECTS_PHASING_CIRC} ${OBJECTS_HASHING_CIRC} ${OBJECTS_MIRACL}
	${CC} ${COMPILER_OPTIONS} -o $@ ${CFLAGS} $^ ${LIBRARIES}


%.o: %.cpp
	${CC} $^ ${COMPILER_OPTIONS} -c ${INCLUDE} ${CFLAGS} ${BATCH} -o $@

.PHONY: clean

clean:
	rm ${OBJECTS}
