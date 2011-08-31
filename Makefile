INCLUDES="."
LINKDIRS=
LINKLIBS=

MAINFILE=socksserver.c

CFLAGS_OWN=-Wall -D_GNU_SOURCE -std=c99
#c99 for firedns compatibility (restrict keyword)
CFLAGS_DBG=-g -O0
CFLAGS_OPT=-s -Os

-include config.mak

CFLAGS_RCB_OPT=${CFLAGS_OWN} ${CFLAGS_OPT} -I ${INCLUDES} ${LINKLIBS} ${CFLAGS}
CFLAGS_RCB_DBG=${CFLAGS_OWN} ${CFLAGS_DBG} -I ${INCLUDES} ${LINKLIBS} ${CFLAGS}

all: debug

optimized:
	CFLAGS="${CFLAGS_RCB_OPT}" rcb --force ${RCBFLAGS} ${MAINFILE}

debug:
	CFLAGS="${CFLAGS_RCB_DBG}" rcb --force ${RCBFLAGS} ${MAINFILE}


.PHONY: all optimized debug
