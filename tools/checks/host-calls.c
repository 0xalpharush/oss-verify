/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * host-calls: run a command with an empty environment, as user <uid>, and under ptrace with every thread and process
 * it starts, and log the host system calls named below with their full arguments and results.
 * tools/checks/run-binaries runs qemu-riscv64 under it.
 *
 *     host-calls <log> <uid> <program> [<argument>...]
 *
 * qemu-riscv64's -strace log prints some arguments of a guest call as 32-bit numbers: the length of mmap, munmap,
 * mprotect and madvise, the offset of mmap, the buffer and count of read and write, the size of getrandom and getcwd.
 * qemu makes the guest's call on the host with the same numbers (with no -R, a guest address is the host address), so
 * the host call shows them in full. Each call of the list below, whether it succeeds or fails, gives one line:
 *
 *     <name> <result, signed decimal> <argument 0> <argument 1> ... <argument 5>     the arguments in hex
 *
 * and the line `exec` when the command's program has started; a log without it is of a run that never started.
 *
 * tools/syscall_shapes.py takes a guest call's full arguments from the first unused line of the same name that agrees
 * with the printed values in their low 32 bits. qemu's own calls (its log, its loading of the program) are in the log
 * too; they agree with no guest call, or only by a coincidence of all the printed bits.
 *
 * The command runs with no environment, so that no QEMU_* variable of the image changes what qemu does, and as <uid>,
 * so that the guest cannot write the results that this run's caller reads. It exits with the command's status, or 128
 * plus the number of the signal that ended it, as a shell reports either. x86-64 hosts only; it is compiled in the
 * run's container, with the image's C compiler.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __x86_64__
#error "host-calls reads x86-64 registers"
#endif

static const char *logged(unsigned long long number) {
  switch (number) {
    case SYS_mmap: return "mmap";
    case SYS_munmap: return "munmap";
    case SYS_mprotect: return "mprotect";
    case SYS_madvise: return "madvise";
    case SYS_mremap: return "mremap";
    case SYS_read: return "read";
    case SYS_write: return "write";
    case SYS_pread64: return "pread64";
    case SYS_pwrite64: return "pwrite64";
    case SYS_getrandom: return "getrandom";
    case SYS_getcwd: return "getcwd";
    case SYS_sendto: return "sendto";
    default: return NULL;
  }
}

int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr, "usage: host-calls <log> <uid> <program> [<argument>...]\n");
    return 2;
  }
  FILE *log = fopen(argv[1], "w");
  if (!log) {
    perror(argv[1]);
    return 2;
  }
  uid_t uid = (uid_t)strtoul(argv[2], NULL, 10);
  pid_t child = fork();
  if (child < 0) {
    perror("fork");
    return 2;
  }
  if (child == 0) {
    char *empty[] = {NULL};
    fclose(log);
    if (setgroups(0, NULL) != 0 || setgid(uid) != 0 || setuid(uid) != 0) _exit(125);
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) _exit(126);
    raise(SIGSTOP);
    execve(argv[3], argv + 3, empty);
    _exit(127);
  }
  int status;
  if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) {
    fprintf(stderr, "host-calls: the command did not start under ptrace (status %d)\n", status);
    return 2;
  }
  /* EXITKILL: if this process ends (the run's time limit kills it), the traced command ends with it. TRACEEXEC: the
   * stop after execve is an event, not a SIGTRAP that would be delivered to the command. */
  long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                 PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL;
  if (ptrace(PTRACE_SETOPTIONS, child, 0, options) != 0) {
    perror("ptrace");
    return 2;
  }
  ptrace(PTRACE_SYSCALL, child, 0, 0);
  int code = 2;
  for (;;) {
    pid_t pid = waitpid(-1, &status, __WALL);
    if (pid < 0) {
      if (errno == EINTR) continue;
      break; /* no traced process is left */
    }
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      if (pid == child) code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
      continue;
    }
    if (!WIFSTOPPED(status)) continue;
    int sig = WSTOPSIG(status), deliver = 0;
    if (sig == (SIGTRAP | 0x80)) {
      /* A system call stop. At its entry the kernel holds -ENOSYS in rax; at its exit, the result. */
      struct user_regs_struct r;
      const char *name;
      if (ptrace(PTRACE_GETREGS, pid, 0, &r) == 0 && (long long)r.rax != -ENOSYS && (name = logged(r.orig_rax)))
        fprintf(log, "%s %lld %llx %llx %llx %llx %llx %llx\n", name, (long long)r.rax, r.rdi, r.rsi, r.rdx, r.r10,
                r.r8, r.r9);
    } else if (sig == SIGTRAP && (status >> 16) != 0) {
      /* a clone, fork, vfork or exec event: a new thread or process is traced, and stops once, below. The command's
       * own exec is logged: a log without it is of a run that never started. */
      if (pid == child && (status >> 16) == PTRACE_EVENT_EXEC) fprintf(log, "exec\n");
    } else if (sig != SIGSTOP) {
      deliver = sig; /* a signal for the command itself */
    }
    ptrace(PTRACE_SYSCALL, pid, 0, deliver);
  }
  fclose(log);
  return code;
}
