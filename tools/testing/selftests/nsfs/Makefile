TEST_PROGS := owner pidns

CFLAGS := -Wall -Werror

all: owner pidns nsowner
owner: owner.c
pidns: pidns.c

clean:
	$(RM) owner pidns

include ../lib.mk
