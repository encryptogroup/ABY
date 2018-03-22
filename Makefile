ABY=aby
TEST=test
BIN=bin
SRC=src
CORE=${SRC}/abycore

# compiler settings
CC=g++

#Most aggressive optimizations, asserts are ignored
#ABY_COMPILER_OPTIONS=-O3 -DNDEBUG
#Optimizations
ABY_COMPILER_OPTIONS=-O2 -std=c++14 -march=native
#DEBUG
#ABY_COMPILER_OPTIONS=-g3 -ggdb -O0 -std=c++11 #-fno-omit-frame-pointer -fsanitize=address #-Wall -Wextra -pedantic

export ABY_COMPILER_OPTIONS

ARCHITECTURE = $(shell uname -m)
ifeq (${ARCHITECTURE},x86_64)
MIRACL_MAKE:=linux64_cpp
GNU_LIB_PATH:=x86_64
ARCH_LIB_PATH:=64
else
MIRACL_MAKE:=linux
GNU_LIB_PATH:=i386
ARCH_LIB_PATH:=32
endif

LIBRARIES=-lgmp -lgmpxx -lpthread ${CORE}/ENCRYPTO_utils/miracl_lib/miracl.a -L /usr/lib -lssl -lcrypto -lrt

# directory for the Miracl submodule and library
MIRACL_LIB_DIR=${CORE}/ENCRYPTO_utils/miracl_lib
SOURCES_MIRACL=${CORE}/ENCRYPTO_utils/Miracl/*
OBJECTS_MIRACL=${MIRACL_LIB_DIR}/*.o

OTEXT_DIR=${CORE}/ot
OTEXT_SUB_DIR=${OTEXT_DIR}/external/ot
OT_SUBDIR_FILES=${OTEXT_SUB_DIR}/baseOT.h ${OTEXT_SUB_DIR}/iknp-ot-ext-rec.cpp ${OTEXT_SUB_DIR}/iknp-ot-ext-rec.h ${OTEXT_SUB_DIR}/iknp-ot-ext-snd.cpp ${OTEXT_SUB_DIR}/iknp-ot-ext-snd.h ${OTEXT_SUB_DIR}/naor-pinkas.cpp ${OTEXT_SUB_DIR}/naor-pinkas.h ${OTEXT_SUB_DIR}/ot-ext.cpp ${OTEXT_SUB_DIR}/ot-ext.h ${OTEXT_SUB_DIR}/ot-ext-snd.cpp ${OTEXT_SUB_DIR}/ot-ext-snd.h ${OTEXT_SUB_DIR}/ot-ext-rec.cpp ${OTEXT_SUB_DIR}/ot-ext-rec.h ${OTEXT_SUB_DIR}/xormasking.h ${OTEXT_SUB_DIR}/maskingfunction.h ${OTEXT_SUB_DIR}/kk-ot-ext-snd.h ${OTEXT_SUB_DIR}/kk-ot-ext-snd.cpp ${OTEXT_SUB_DIR}/kk-ot-ext-rec.h ${OTEXT_SUB_DIR}/kk-ot-ext-rec.cpp ${OTEXT_SUB_DIR}/kk-ot-ext.h
OT_FILES=${OTEXT_DIR}/baseOT.h ${OTEXT_DIR}/iknp-ot-ext-rec.cpp ${OTEXT_DIR}/iknp-ot-ext-rec.h ${OTEXT_DIR}/iknp-ot-ext-snd.cpp ${OTEXT_DIR}/iknp-ot-ext-snd.h ${OTEXT_DIR}/naor-pinkas.cpp ${OTEXT_DIR}/naor-pinkas.h ${OTEXT_DIR}/ot-ext.cpp ${OTEXT_DIR}/ot-ext.h ${OTEXT_DIR}/ot-ext-snd.cpp ${OTEXT_DIR}/ot-ext-snd.h ${OTEXT_DIR}/ot-ext-rec.cpp ${OTEXT_DIR}/ot-ext-rec.h ${OTEXT_DIR}/xormasking.h ${OTEXT_DIR}/maskingfunction.h ${OTEXT_DIR}/kk-ot-ext-snd.h ${OTEXT_DIR}/kk-ot-ext-snd.cpp ${OTEXT_DIR}/kk-ot-ext-rec.h ${OTEXT_DIR}/kk-ot-ext-rec.cpp ${OTEXT_DIR}/kk-ot-ext.h

# all source files and corresponding object files in abycore
SOURCES_CORE := $(shell find ${CORE} -type f -name '*.cpp' -not -path '*/ENCRYPTO_utils/miracl_lib/*' -not -path '*/ot/external/*')
#OBJECTS_CORE := $(SOURCES_CORE:.cpp=.o)
OBJECTS_CORE := $(shell find ${CORE} -type f -name '*.o' -not -path '*/ENCRYPTO_utils/miracl_lib/*' -not -path '*/ot/external/*')


# objects in example (sub-)folders
OBJECTS_EXAMPLE = $(shell find ${SRC}/examples -type f -name '*.o')

#objects in test (sub-) folders
OBJECTS_TEST = $(shell find ${SRC}/${TEST} -type f -name '*.o')

# all sub-directories of ${SRC}/examples with their full path
EXAMPLE_SUBDIRS := $(realpath $(wildcard ${SRC}/examples/*/.))

all: miracl otext core examples ${TEST}
	@echo "make all done."

# this will create a copy of the files in src/ENCRYPTO_utils/Miracl and its sub-directories and put them into src/ENCRYPTO_utils/miracl_lib without sub-directories, then compile it
miracl:	${MIRACL_LIB_DIR}/miracl.a

# copy Miracl files to a new directory (${CORE}/ENCRYPTO_utils/miracl_lib/), call the build script and delete everything except the archive, header and object files.
${MIRACL_LIB_DIR}/miracl.a: ${SOURCES_MIRACL}
	@find ${CORE}/ENCRYPTO_utils/Miracl/ -type f -exec cp '{}' ${CORE}/ENCRYPTO_utils/miracl_lib \;
	@cd ${CORE}/ENCRYPTO_utils/miracl_lib/; bash ${MIRACL_MAKE}; find . -type f -not -name '*.a' -not -name '*.h' -not -name '*.o' -not -name '.git*'| xargs rm

# this will create a copy of the files in src/abycore/ot/external/ot/ and put them into src/abycore/ot where they are then used for compiling.
# it does not override files in the ot dir!
otext: miracl
	@cp -n ${OT_SUBDIR_FILES} ${OTEXT_DIR}


core: miracl otext ${OBJECTS_CORE}

%.o:%.cpp %.h
	${CC} $< ${ABY_COMPILER_OPTIONS} -c -o $@

%.o:%.cpp
	${CC} $< ${ABY_COMPILER_OPTIONS} -c -o $@

# check that core is built, then call test makefile
${TEST}: miracl otext core examples
	@(cd ${SRC}/${TEST}; if [ -e Makefile ]; then $(MAKE); fi)

# this will run the previously compiled test-aby executables #TODO: take care of the output and errors
runtest: ${TEST}
	sh runtest_scr.sh

examples: miracl otext core ${EXAMPLE_SUBDIRS}

# if there is a Makefile for an example, then make it
${EXAMPLE_SUBDIRS}:
	@(cd $@; if [ -e Makefile ]; then $(MAKE) -C $@; fi)

.PHONY: clean cleanall examples ${EXAMPLE_SUBDIRS} all ${TEST} miracl runtest core otext

# only clean example objects, test object and binaries
clean:
	rm -f ${OBJECTS_EXAMPLE} ${OBJECTS_TEST} ${BIN}/*.exe
# clean example objects, test object, aby core objects and binaries
cleanmore: clean
	rm -f ${OBJECTS_CORE}

# clean example objects, test object, aby core objects, binaries and OTExtension
cleanmost: cleanmore
	rm -f ${OT_FILES}

# this will clean everything(!): example objects, test object and binaries and the Miracl library, the copied OT files
cleanall: cleanmore
	rm -f ${OBJECTS_MIRACL} ${MIRACL_LIB_DIR}/*.a ${OT_FILES}
