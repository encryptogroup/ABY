#Special Makefile for bench_operations. Not a symlink to ../../Example_Makefile !

#DO NOT MODIFY THIS FILE, unless you know what you're doing

#You should not need to call this makefile separately. It will me called from the Makefile in the root directory

#relative project folders
BIN = ../../../bin
SRC = ../..
CORE=${SRC}/abycore
AES = ../aes/common

SOURCES := $(shell find . -type f -name '*.cpp')
OBJECTS := $(patsubst %.cpp, %.o, ${SOURCES})

# all source files and corresponding object files in abycore
SOURCES_CORE := $(shell find ${CORE} -type f -name '*.cpp' -not -path '*/util/Miracl/*' -not -path '*/ot/external/*')
OBJECTS_CORE := $(SOURCES_CORE:.cpp=.o)

SOURCES_AES := $(shell find ${AES} -type f -name '*.cpp')
OBJECTS_AES := $(SOURCES_AES:.cpp=.o)

# directory for the Miracl library
MIRACL_LIB_DIR=${CORE}/util/miracl_lib
OBJECTS_MIRACL=${MIRACL_LIB_DIR}/*.o

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
INCLUDE=-I..  -I/usr/include/glib-2.0/ -I/usr/lib/${GNU_LIB_PATH}-linux-gnu/glib-2.0/include
CFLAGS=
LIBRARIES=-lgmp -lgmpxx -lpthread ${CORE}/util/miracl_lib/miracl.a -L /usr/lib  -lssl -lcrypto -lglib-2.0 -lrt

#take the current directory's name as name for the executable in ${BIN}
EXAMPLE = $(lastword $(subst /, ,${CURDIR}))

all: 
	${CC} ${COMPILER_OPTIONS} ${CFLAGS} ${LIBRARIES} ${INCLUDE} -c bench_operations.cpp -o bench_operations.o
	${CC} ${COMPILER_OPTIONS} ${CFLAGS} ${OBJECTS} ${OBJECTS_AES} ${OBJECTS_CORE} ${OBJECTS_MIRACL}  ${LIBRARIES} ${INCLUDE}  -o ${BIN}/${EXAMPLE}.exe

.PHONY: clean

clean:
	rm ${OBJECTS}
