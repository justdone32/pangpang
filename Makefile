PROJECT=bin/pangpang
CPPSRC=$(shell find src -type f -name *.cpp)
CPPOBJ=$(patsubst %.cpp,%.o,$(CPPSRC))
CSRC=$(shell find src -type f -name *.c)
COBJ=$(patsubst %.c,%.o,$(CSRC))
OBJ=$(CPPOBJ)
OBJ+=$(COBJ)

CFLAGS=
CXXFLAGS=-std=c++11 -O3 -Wall -Isrc/inc -Isrc/lib -Isrc/lib/MPFDParser-1.1.1 `pkg-config --cflags hiredis libevent_openssl openssl`
LDLIBS=`pkg-config --libs hiredis libevent_openssl openssl` -lpcre -lz -lpthread -ldl

PREFIX=/usr/local/pangpang

all:$(PROJECT)

$(PROJECT):$(OBJ)
	g++ -o $@ $^ $(LDLIBS)

.c.o:
	gcc $(CFLAGS) -c $^ -o $@

.cpp.o:
	g++ $(CXXFLAGS)  -c $^ -o $@


clean:
	@for i in $(OBJ);do echo $${i} ;done
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
	install --backup conf/pangpang.json $(PREFIX)/conf
	install --backup conf/pattern.conf $(PREFIX)/conf
	install --backup conf/zlog.conf $(PREFIX)/conf
	install --backup html/index.html $(PREFIX)/html
	cp systemctl/pangpang.service /etc/systemd/system
