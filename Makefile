PROJECT=bin/pangpang
SRC=$(wildcard  src/lib/*.cpp src/lib/MPFDParser-1.1.1/*.cpp src/*.cpp)
OBJ=$(patsubst %.cpp,%.o,$(SRC))
CC=g++
CXXFLAGS=-std=c++11 -O3 -Wall -Isrc/inc -Isrc/lib -Isrc/lib/MPFDParser-1.1.1 `pkg-config --cflags hiredis  libevent_openssl openssl`
LDLIBS=`pkg-config --libs hiredis libevent_openssl openssl` -lz -lpthread -ldl

PREFIX=/usr/local/pangpang

all:$(PROJECT)

$(PROJECT):$(OBJ)
	$(CC) -o $@ $^ $(CXXFLAGS) $(LDLIBS)
	
clean:
	rm -f $(PROJECT) $(OBJ)

install:
	test -d $(PREFIX) || mkdir -p $(PREFIX)
	test -d $(PREFIX)/include || mkdir -p $(PREFIX)/include
	test -d $(PREFIX)/bin || mkdir -p $(PREFIX)/bin
	test -d $(PREFIX)/html || mkdir -p $(PREFIX)/html
	test -d $(PREFIX)/logs || mkdir -p $(PREFIX)/logs
	test -d $(PREFIX)/conf || mkdir -p $(PREFIX)/conf
	test -d $(PREFIX)/mod || mkdir -p $(PREFIX)/mod
	test -d $(PREFIX)/temp || mkdir -p $(PREFIX)/temp
	cp src/inc/*.hpp $(PREFIX)/include
	install bin/pangpang $(PREFIX)/bin
	test -f $(PREFIX)/conf/pangpang.json || install conf/pangpang.json $(PREFIX)/conf
	test -f $(PREFIX)/conf/pattern.conf  || install conf/pattern.conf $(PREFIX)/conf
	install html/index.html $(PREFIX)/html
	cp systemctl/pangpang.service /etc/systemd/system
