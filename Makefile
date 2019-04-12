INCLUDES="."
LINKDIRS=
LINKLIBS=

FNAME=socksserver
MAINFILE=$(FNAME).c

-include config.mak

CFLAGS_OWN=-Wall -D_GNU_SOURCE -std=c99 -static $(CFLAGS)
#c99 for firedns compatibility (restrict keyword)
CFLAGS_DBG=-g -O0
CFLAGS_OPT=-s -Os -flto -fwhole-program
CFLAGS_OPT_HEAVY=$(CFLAGS_OPT) -flto -fwhole-program -fno-asynchronous-unwind-tables -nostartfiles $(MUSL_DIR)/lib/crt1.o

RCB=rcb2

CFLAGS_RCB_OPTH=${CFLAGS_OWN} ${CFLAGS_OPT_HEAVY} -I ${INCLUDES} ${LINKLIBS} ${CFLAGS}
CFLAGS_RCB_OPT=${CFLAGS_OWN} ${CFLAGS_OPT} -I ${INCLUDES} ${LINKLIBS} ${CFLAGS}
CFLAGS_RCB_DBG=${CFLAGS_OWN} ${CFLAGS_DBG} -I ${INCLUDES} ${LINKLIBS} ${CFLAGS}

all: debug

clean:
	rm $(FNAME).rcb $(FNAME).out $(FNAME).o

optimized-heavy:
	CFLAGS="${CFLAGS_RCB_OPTH}" $(RCB) ${RCBFLAGS} ${MAINFILE}
	strip --remove-section .comment $(FNAME).out
	strip --remove-section .comment.SUSE.OPTs $(FNAME).out

optimized:
	CFLAGS="${CFLAGS_RCB_OPT}" $(RCB) ${RCBFLAGS} ${MAINFILE}
	strip --remove-section .comment $(FNAME).out

debug:
	CFLAGS="${CFLAGS_RCB_DBG}" $(RCB) ${RCBFLAGS} ${MAINFILE}


.PHONY: all optimized debug
