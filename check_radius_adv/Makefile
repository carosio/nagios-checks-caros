# Generated automatically from Makefile.in by configure.
CC=gcc
DEBUG=-O3
DEFINES=
CFLAGS=-Wall ${DEFINES} ${DEBUG} -c
LFLAGS=-Wall ${DEFINES} ${DEBUG} -o
OBJS=check_radius_adv.o md5.o
BIN=check_radius_adv
LIBS= -lnsl

all: ${OBJS}
	${CC} ${LFLAGS} ${BIN} ${OBJS} ${LIBS}

check_radius_adv.o: check_radius_adv.c
	${CC} ${CFLAGS} check_radius_adv.c -o check_radius_adv.o

md5.o: md5.c
	${CC} ${CFLAGS} md5.c -o md5.o

install: ${OBJS}
	cp check_radius_adv /usr/local/bin/check_radius_adv
	chmod 755 /usr/local/bin/check_radius_adv

distclean:
	rm -f core ${BIN} *.o config.status config.cache Makefile config.log

clean:
	rm -f core ${BIN} *.o
