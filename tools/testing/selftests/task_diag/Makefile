all: task_diag task_diag_all fork task_proc_all

run_tests: all
	@./task_diag && ./task_diag_all && echo "task_diag: [PASS]" || echo "task_diag: [FAIL]"

CFLAGS += -Wall -O2

task_diag.o: task_diag.c task_diag_comm.h
task_diag_all.o: task_diag_all.c task_diag_comm.h
task_diag_comm.o: task_diag_comm.c task_diag_comm.h

task_diag_all: task_diag_all.o task_diag_comm.o
task_diag: task_diag.o task_diag_comm.o
fork: fork.c
task_proc_all: task_proc_all.c

clean:
	rm -rf task_diag task_diag_all task_diag_comm.o task_diag_all.o task_diag.o fork task_proc_all
