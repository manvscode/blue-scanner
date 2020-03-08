# To build for Linux:
# 	make OS=linux
#
# To build for Windows i686:
# 	make OS=windows-i686
#
# To build for Windows x86_64:
# 	make OS=windows-x86_64
#
# To install:
# 	make install INSTALL_PATH=~/bin
#

ifndef $(OS)
OS=linux
endif

ifndef $(DEBUG)
DEBUG=false
endif

CWD = $(shell pwd)

ifeq ($(DEBUG), true)
CFLAGS = -std=c99 -Wall -O0 -g -fsanitize=undefined -I /usr/local/include -I extern/include/
else
CFLAGS = -std=c99 -Wall -O2 -I /usr/local/include -I extern/include/utility-1.0.0/ -I extern/include/collections-1.0.0/
endif

ifeq ($(OS),linux)
BIN_NAME = blue-scanner
CC = gcc
HOST=
CFLAGS += -D_POSIX_C_SOURCE=200112L
LDFLAGS = extern/lib/libutility.a extern/lib/libcollections.a -L /usr/local/lib -L extern/lib/ -L extern/libcollections/lib/
endif

ifeq ($(OS),windows-i686)
BIN_NAME = blue-scanner-i686.exe
CC=i686-w64-mingw32-gcc
HOST=i686-w64-mingw32
CFLAGS += -D_POSIX -DWINVER=WindowsVista -D_WIN32_WINDOWS=WindowsVista -D_WIN32_WINNT=WindowsVista
LDFLAGS = extern/lib/libutility.a extern/lib/libcollections.a -L /usr/local/lib -L extern/lib/ -L extern/libcollections/lib/ -L /usr/i686-w64-mingw32/lib/ -lmingw32 -lmsvcrt -lws2_32
endif

ifeq ($(OS),windows-x86_64)
BIN_NAME = blue-scanner-x86_64.exe
CC=x86_64-w64-mingw32-gcc
HOST=x86_64-w64-mingw32
CFLAGS += -D_POSIX -DWINVER=WindowsVista -D_WIN32_WINDOWS=WindowsVista -D_WIN32_WINNT=WindowsVista
LDFLAGS = extern/lib/libutility.a extern/lib/libcollections.a -L /usr/local/lib -L extern/lib/ -L extern/libcollections/lib/ -L /usr/x86_64-w64-mingw32/lib/ -lmingw32 -lmsvcrt -lws2_32
endif

SOURCES = src/main.c

all: extern/libutility extern/libcollections bin/$(BIN_NAME)

bin/$(BIN_NAME): $(SOURCES:.c=.o)
	@mkdir -p bin
	@echo "Linking: $^"
	@$(CC) $(CFLAGS) -o bin/$(BIN_NAME) $^ $(LDFLAGS)
	@echo "Created $@"

src/%.o: src/%.c
	@echo "Compiling: $<"
	@$(CC) $(CFLAGS) -c $< -o $@

#################################################
# Dependencies                                  #
#################################################
extern/libutility:
	@mkdir -p extern/libutility/
	@git clone https://bitbucket.org/manvscode/libutility.git extern/libutility/
	@cd extern/libutility && autoreconf -fi && ./configure --libdir=$(CWD)/extern/lib/ --includedir=$(CWD)/extern/include/ --host=$(HOST) && make && make install

extern/libcollections:
	@mkdir -p extern/libcollections/
	@git clone https://bitbucket.org/manvscode/libcollections.git extern/libcollections/
	@cd extern/libcollections && autoreconf -fi && ./configure --libdir=$(CWD)/extern/lib/ --includedir=$(CWD)/extern/include/ --host=$(HOST) && make && make install

#################################################
# Cleaning                                      #
#################################################
clean_extern:
	@rm -rf extern

clean:
	@rm -rf src/*.o
	@rm -rf bin

#################################################
# Installing                                    #
#################################################
install:
ifeq ("$(INSTALL_PATH)","")
	$(error INSTALL_PATH is not set.)
endif
	@echo "Installing ${CWD}/bin/${BIN_NAME} to ${INSTALL_PATH}"
	@cp bin/$(BIN_NAME) $(INSTALL_PATH)/$(BIN_NAME)
