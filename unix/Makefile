TARGETS = ipproof-client ipproof-server

CC := gcc
CFLAGS :=-pipe -g -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE -I../src/
CWARNINGS := -Wall -Wextra -pipe -Wwrite-strings -Wsign-compare \
					-Wshadow -Wformat=2 -Wundef -Wstrict-prototypes   \
					-fno-strict-aliasing -fno-common -Wformat-security \
					-Wformat-y2k -Winit-self -Wredundant-decls \
					-Wstrict-aliasing=3 -Wswitch-default -Wswitch-enum \
					-Wno-system-headers -Wundef -Wvolatile-register-var \
					-Wcast-align -Wbad-function-cast -Wwrite-strings \
					-Wold-style-definition  -Wdeclaration-after-statement \
					-fstack-protector

CLIBS=-lm

CFLAGS += -ggdb3 # -Werror

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(TARGETS)

clean:
	@rm -f $(TARGETS) core ~*

%: %.c Makefile global.h
	$(CC) $(CFLAGS) $(CWARNINGS) -o $@ $<

ipproof-client: ../src/client.c ../src/shared.c
	$(CC) $(CFLAGS) $(CWARNINGS) -o ipproof-client ../src/client.c ../src/shared.c

ipproof-server: ../src/server.c ../src/shared.c
	$(CC) $(CFLAGS) $(CWARNINGS) $(CLIBS) -o ipproof-server ../src/server.c ../src/shared.c

install: ipproof-server ipproof-client
	install ipproof-server /usr/bin
	install ipproof-client /usr/bin

cscope:
	cscope -R -b


