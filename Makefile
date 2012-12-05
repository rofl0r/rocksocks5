INCLUDES="."
LINKDIRS=
LINKLIBS=

FNAME=socksserver
MAINFILE=$(FNAME).c

CFLAGS_OWN=-Wall -D_GNU_SOURCE -std=c99 -static
#c99 for firedns compatibility (restrict keyword)
CFLAGS_DBG=-g -O0
CFLAGS_OPT=-s -Os
CFLAGS_OPT_HEAVY=$(CFLAGS_OPT) -flto -fwhole-program -fno-asynchronous-unwind-tables -nostartfiles $(MUSL_DIR)/lib/crt1.o

-include config.mak

CFLAGS_RCB_OPTH=${CFLAGS_OWN} ${CFLAGS_OPT_HEAVY} -I ${INCLUDES} ${LINKLIBS} ${CFLAGS}
CFLAGS_RCB_OPT=${CFLAGS_OWN} ${CFLAGS_OPT} -I ${INCLUDES} ${LINKLIBS} ${CFLAGS}
CFLAGS_RCB_DBG=${CFLAGS_OWN} ${CFLAGS_DBG} -I ${INCLUDES} ${LINKLIBS} ${CFLAGS}

all: debug

clean:
	rm $(FNAME).rcb $(FNAME).out $(FNAME).o

optimized-heavy:
	CFLAGS="${CFLAGS_RCB_OPTH}" rcb --force ${RCBFLAGS} ${MAINFILE}
	strip --remove-section .comment $(FNAME).out
	strip --remove-section .comment.SUSE.OPTs $(FNAME).out

optimized:
	CFLAGS="${CFLAGS_RCB_OPT}" rcb --force ${RCBFLAGS} ${MAINFILE}
	strip --remove-section .comment $(FNAME).out

debug:
	CFLAGS="${CFLAGS_RCB_DBG}" rcb --force ${RCBFLAGS} ${MAINFILE}


.PHONY: all optimized debug
