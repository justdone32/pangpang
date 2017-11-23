PROJECT=bin/pangpang
SRC=$(wildcard  src/lib/*.cpp src/*.cpp)
OBJ=$(patsubst %.cpp,%.o,$(SRC))
CC=g++
CXXFLAGS=-std=c++11 -O3 -Wall -Isrc/inc -Isrc/lib `pkg-config --cflags hiredis  libevent_openssl openssl`
LDLIBS=`pkg-config --libs hiredis libevent_openssl openssl` -lpthread -ldl

all:$(PROJECT)

$(PROJECT):$(OBJ)
	$(CC) -o $@ $^ $(CXXFLAGS) $(LDLIBS)
	
clean:
	rm -f $(PROJECT) $(OBJ)

install:
	@echo install