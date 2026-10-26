# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/syscall_shapes.py: python3 -m pytest -q -p no:cacheprovider tools/tests/test_syscall_shapes.py

Most cases need the process model: set OSS_VERIFY_MODEL to a checkout of the published model (the directory that holds
theories/) at syscall_shapes.MODEL_COMMIT. Without it they are skipped, and say so; the trace parser, the host-call
log reader, the image reader and the 32-bit argument reader are tested either way.

The planted traces are what qemu-riscv64 -strace prints: the formats of linux-user/strace.list and strace.c at v8.2.2
and v10.0.11 (rt_sigaction prints three arguments, mmap's length through `%d`, a record with no printer prints six
64-bit decimals, and so on). Each one names the condition it is about, and is a trace the checker must accept or one
it must refuse: a checker that cannot refuse tests nothing. Each run also needs its host-call log; faithful_log()
writes the log of a run whose printed arguments are its true ones, and the cases about cut arguments write their own.
"""
import os
import pathlib
import struct
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import model_release  # noqa: E402
import syscall_shapes as S  # noqa: E402
from check_build import Failed  # noqa: E402

MODEL_ENV = "OSS_VERIFY_MODEL"
MODEL_ROOT = os.environ.get(MODEL_ENV)
needs_model = pytest.mark.skipif(not MODEL_ROOT, reason=f"{MODEL_ENV} is not set: no checkout of the published model "
                                                        "to read the arms from")
MODEL_FILES_READ = ("Sys/SyscallTable.v", "Specs.v", "Sys/Mm/Mmap.v", "Sys/Mm/Madvise.v", "Sys/Uapi.v", "State.v")


def elf_bytes(loads, machine=S.EM_RISCV):
    """A minimal 64-bit little-endian ELF file with one program header per (vaddr, memsz) in `loads`, all LOAD."""
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", header, 16, 2, machine, 1, 0x10000, 64, 0, 0, 64, 56, len(loads), 0, 0, 0)
    phdrs = b"".join(struct.pack("<IIQQQQQQ", S.PT_LOAD, 5, 0, vaddr, vaddr, 0, memsz, 0x1000)
                     for vaddr, memsz in loads)
    return bytes(header) + phdrs


def faithful_log(trace, *, started=True, extra=()):
    """The host-call log (tools/checks/host-calls.c) of a run whose printed arguments are its true ones: the `exec`
    line, then one line per record of a call the tracer logs, with the values qemu printed. `extra` adds lines."""
    lines = ["exec"] if started else []
    for line in trace.splitlines():
        for _, name, args, tail, closed in S.split_records(line):
            if name not in S.HOST_NAMES or not closed:
                continue
            values = [(S.num(a) or 0) % (1 << 64) for a in (list(args) + ["0"] * 6)[:6]]
            ret = S.parse_ret(tail)
            lines.append(" ".join([name, str(ret if ret is not None else 0)] + [f"{v:x}" for v in values]))
    return "\n".join(lines + list(extra)) + "\n"


@pytest.fixture(scope="session")
def model():
    return S.Model.load(MODEL_ROOT)


@pytest.fixture(scope="session")
def image(tmp_path_factory):
    """A binary whose image is [0x10000, 0x12000): the planted traces keep clear of it unless they are about it."""
    path = tmp_path_factory.mktemp("image") / "target.plain"
    path.write_bytes(elf_bytes([(0x10000, 0x2000)]))
    return str(path)


def check(model, image, text, stance="off", require_exit=True, lengths=None):
    return S.check_trace(model, text, stance=stance, require_exit=require_exit, binary=image,
                         lengths=faithful_log(text) if lengths is None else lengths)


def whys(result):
    return [u["why"] for u in result["unmodeled"]]


def one_undecided(result, call=None):
    """The one reason a trace decided nothing: a call the model's answer turns on a value the trace cannot show."""
    assert result["verdict"] == "undecided", result
    assert result["unmodeled"] == [], result["unmodeled"]
    assert len(result["undecided"]) == 1, result["undecided"]
    if call is not None:
        assert result["undecided"][0]["call"] == call, result["undecided"]
    return result["undecided"][0]["why"]


def one_why(result, call=None):
    assert result["verdict"] == "fail", result
    assert len(result["unmodeled"]) == 1, result["unmodeled"]
    if call is not None:
        assert result["unmodeled"][0]["call"] == call, result["unmodeled"]
    return result["unmodeled"][0]["why"]


def model_copy(tmp_path, edit=None):
    """A copy of the files Model.load reads, with `edit(rel, text) -> text` applied to each: a checkout to break."""
    for rel in MODEL_FILES_READ:
        src = pathlib.Path(MODEL_ROOT) / S.MODEL_DIR / rel
        dst = tmp_path / S.MODEL_DIR / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        text = src.read_text(encoding="utf-8")
        dst.write_text(edit(rel, text) if edit else text, encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------------------------------------------------
# The planted traces
# ---------------------------------------------------------------------------------------------------------------------
EXIT = "1 exit_group(0)"
OPEN3 = '1 openat(AT_FDCWD,"in.bin",O_RDONLY|O_LARGEFILE) = 3\n'       # a read-only file at descriptor 3
OPENDIR3 = '1 openat(AT_FDCWD,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC) = 3\n'
SOCKET3 = "1 socket(PF_INET,SOCK_STREAM|SOCK_CLOEXEC,IPPROTO_IP) = 3\n"
TID = "1 set_tid_address(0x64dbf0) = 1\n"                              # pins the model's m_tid at 1
GUARD_IN_BRK = ("1 brk(NULL) = 0x100000\n1 brk(0x102000) = 0x102000\n"
                "1 mmap(0x100000,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = 0x100000\n" + EXIT)
TMP_ROUND_TRIP = ('1 openat(AT_FDCWD,"/tmp/libfuzzer.1",O_WRONLY|O_CREAT|O_TRUNC,0600) = 3\n'
                  '1 write(3,0x1000,20) = 20\n1 close(3) = 0\n'
                  '1 openat(AT_FDCWD,"/tmp/libfuzzer.1",O_RDONLY) = 3\n'
                  '1 read(3,0x1000,20) = 20\n1 close(3) = 0\n'
                  '1 unlinkat(AT_FDCWD,"/tmp/libfuzzer.1",0) = 0\n' + EXIT)
MADVISE_GRANT = ("1 mmap(NULL,262144,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE,-1,0)"
                 " = 0x0000000000100000\n")
GRANT_NONE = "1 mmap(NULL,65536,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE,-1,0) = 0x100000\n"
COMMIT = "1 mmap(0x104000,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = 0x104000\n"
BRK_GUARD = ("1 brk(NULL) = 0x100000\n1 brk(0x102000) = 0x102000\n"
             "1 mmap(0x101000,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = 0x101000\n")

ACCEPT = [
    # -- the address space -------------------------------------------------------------------------------------------
    ("the plain rw anonymous grant",
     "1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x100000\n" + EXIT),
    ("a fresh inaccessible reservation",
     "1 mmap(NULL,8192,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x100000\n" + EXIT),
    ("a guard page inside a brk grant", GUARD_IN_BRK),
    ("an exact munmap of a tracked mapping",
     "1 mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x100000\n"
     "1 munmap(0x100000,8192) = 0\n" + EXIT),
    ("mprotect of a read-write grant",
     MADVISE_GRANT + "1 mprotect(0x100000,4096,PROT_READ|PROT_WRITE) = 0\n" + EXIT),
    ("mprotect of a PROT_NONE reservation", GRANT_NONE + "1 mprotect(0x100000,8192,PROT_READ|PROT_WRITE) = 0\n"
     + EXIT),
    ("an rw grant with MAP_NORESERVE",
     "1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE,-1,0) = 0x100000\n" + EXIT),
    ("an rw MAP_FIXED commit inside a tracked reservation", GRANT_NONE + COMMIT + EXIT),
    ("an rw MAP_FIXED grant over free memory",
     "1 mmap(0x100000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_NORESERVE,-1,0) = 0x100000\n"
     + EXIT),
    ("a MAP_FIXED guard page in no tracked mapping",
     "1 mmap(0x100000,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = 0x100000\n" + EXIT),
    ("an rw MAP_FIXED across the end of its owner (the spanning arm)",
     "1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x100000\n"
     "1 mmap(0x100000,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = 0x100000\n" + EXIT),
    ("an rw MAP_FIXED ending at the smallest alloc_top",
     "1 mmap(0x7fff7f7ff000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = 0x7fff7f7ff000\n"
     + EXIT),
    ("a munmap of a free range below the smallest alloc_top", "1 munmap(0x8000000000,4096) = 0\n" + EXIT),
    ("a munmap past TASK_SIZE, -EINVAL", "1 munmap(0x800000000000,4096) = -1 errno=22\n" + EXIT),
    ("an mmap with an offset not page-aligned, -EINVAL",
     "1 mmap(NULL,4096,PROT_READ,MAP_SHARED,3,1) = -1 errno=22\n" + EXIT),
    ("an anonymous rw mmap with an fd",
     "1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,3,0) = 0x100000\n" + EXIT),
    ("an anonymous mmap that failed with -ENOMEM",
     "1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = -1 errno=12\n" + EXIT),
    ("a zero-length mmap, -EINVAL",
     "1 mmap(NULL,0,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = -1 errno=22\n" + EXIT),
    ("mremap to the same rounded size",
     MADVISE_GRANT + "1 mremap(1048576,262144,262144,1,0,0) = 1048576\n" + EXIT),
    ("an mremap shrink in place", MADVISE_GRANT + "1 mremap(1048576,262144,131072,1,0,0) = 1048576\n" + EXIT),
    ("an mremap grow in place over free memory",
     MADVISE_GRANT + "1 mremap(1048576,262144,524288,1,0,0) = 1048576\n" + EXIT),
    ("an mremap move to a free range",
     MADVISE_GRANT + "1 mmap(0x200000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = 0x200000\n"
     "1 mremap(1048576,262144,524288,1,0,0) = 4194304\n" + EXIT),
    ("an mremap that failed with -ENOMEM",
     MADVISE_GRANT + "1 mremap(1048576,262144,524288,1,0,0) = -1 errno=12\n" + EXIT),
    # -- the MAP_FIXED_NOREPLACE arms --------------------------------------------------------------------------------
    ("the ASan low shadow: rw MAP_FIXED_NOREPLACE|MAP_NORESERVE over free memory",
     "1 mmap(0x000000007fff7000,268435456,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE|"
     "MAP_NORESERVE,-1,0) = 0x000000007fff7000\n" + EXIT),
    ("PROT_NONE with MAP_FIXED|MAP_FIXED_NOREPLACE|MAP_NORESERVE",
     "1 mmap(0x000000008fff7000,8192,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_FIXED_NOREPLACE|MAP_NORESERVE,"
     "-1,0) = 0x000000008fff7000\n" + EXIT),
    ("a MAP_FIXED_NOREPLACE reservation, then an rw MAP_FIXED commit inside it",
     "1 mmap(0x100000,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE|MAP_NORESERVE,-1,0) = "
     "0x100000\n1 mmap(0x101000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = 0x101000\n"
     + EXIT),
    ("MAP_FIXED_NOREPLACE over a tracked grant, -EEXIST",
     "1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x100000\n"
     "1 mmap(0x100000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE|MAP_NORESERVE,-1,0) = -1 "
     "errno=17 (File exists)\n" + EXIT),
    ("MAP_FIXED_NOREPLACE over free memory, -ENOMEM",
     "1 mmap(0x100000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0) = -1 errno=12 "
     "(Cannot allocate memory)\n" + EXIT),
    # -- madvise -----------------------------------------------------------------------------------------------------
    ("DONTNEED over part of one rw grant", MADVISE_GRANT + "1 madvise(0x110000,126976,MADV_DONTNEED) = 0\n" + EXIT),
    ("DONTNEED over a whole rw grant", MADVISE_GRANT + "1 madvise(0x100000,262144,MADV_DONTNEED) = 0\n" + EXIT),
    ("DONTNEED over a brk grow",
     "1 brk(NULL) = 0x100000\n1 brk(0x102000) = 0x102000\n1 madvise(0x100000,8192,MADV_DONTNEED) = 0\n" + EXIT),
    ("DONTNEED printed as a number", MADVISE_GRANT + "1 madvise(0x100000,4096,0x4) = 0\n" + EXIT),
    ("DONTNEED at an unaligned address, -EINVAL",
     "1 madvise(0x100001,4096,MADV_DONTNEED) = -1 errno=22 (Invalid argument)\n" + EXIT),
    ("a zero-length DONTNEED", MADVISE_GRANT + "1 madvise(0x100000,0,MADV_DONTNEED) = 0\n" + EXIT),
    # -- files and descriptors ---------------------------------------------------------------------------------------
    ("a read-only openat with O_LARGEFILE", OPEN3 + EXIT),
    ("an O_DIRECTORY open of the working directory", OPENDIR3 + EXIT),
    ("an openat with O_NONBLOCK", '1 openat(AT_FDCWD,"in.bin",O_RDONLY|O_NONBLOCK) = 3\n' + EXIT),
    ("openat with O_RDWR", '1 openat(AT_FDCWD,"f",O_RDWR|O_LARGEFILE) = 3\n' + EXIT),
    ("openat with O_RDWR|O_CREAT|O_TRUNC", '1 openat(AT_FDCWD,"f",O_RDWR|O_CREAT|O_TRUNC,0644) = 3\n' + EXIT),
    ("an append create", '1 openat(AT_FDCWD,"log",O_WRONLY|O_CREAT|O_APPEND,0644) = 3\n' + EXIT),
    ("the /tmp round trip: create, write, close, read back, remove", TMP_ROUND_TRIP),
    ("unlinkat -ENOENT of a /tmp key never created, twice",
     '1 unlinkat(AT_FDCWD,"/tmp/fuzz-test.zip",0) = -1 errno=2\n'
     '1 unlinkat(AT_FDCWD,"/tmp/fuzz-test.zip",0) = -1 errno=2\n' + EXIT),
    ("a /tmp create alone", '1 openat(AT_FDCWD,"/tmp/fuzz-test.zip",O_WRONLY|O_CREAT|O_TRUNC,0600) = 3\n' + EXIT),
    ("/dev/null opened for writing", '1 openat(AT_FDCWD,"/dev/null",O_WRONLY|O_CREAT|O_TRUNC,0644) = 3\n' + EXIT),
    ("/etc/localtime answered -ENOENT",
     '1 openat(AT_FDCWD,"/etc/localtime",O_RDONLY|O_CLOEXEC|O_NONBLOCK) = -1 errno=2\n' + EXIT),
    ("/dev/urandom opened read-only", '1 openat(AT_FDCWD,"/dev/urandom",O_RDONLY|O_CLOEXEC) = 3\n' + EXIT),
    ("a create answered -EACCES", '1 openat(AT_FDCWD,"f",O_WRONLY|O_CREAT|O_TRUNC,0644) = -1 errno=13\n' + EXIT),
    ("unlinkat of a bare name", '1 unlinkat(AT_FDCWD,"gzio_tmp.gz",0) = 0\n' + EXIT),
    ("unlinkat of a name with a trailing separator, -ENOTDIR",
     '1 unlinkat(AT_FDCWD,"gzio_tmp.gz/",0) = -1 errno=20\n' + EXIT),
    ("close of an open descriptor", OPEN3 + "1 close(3) = 0\n" + EXIT),
    ("close of a descriptor the run never opened, -EBADF", "1 close(9) = -1 errno=9\n" + EXIT),
    ("fstat of a file descriptor", OPEN3 + "1 fstat(3,0x40007ff8b0) = 0\n" + EXIT),
    ("newfstatat of an absent key answered -ENOENT",
     '1 newfstatat(AT_FDCWD,"absent.bin",0x40007ff8b0,0) = -1 errno=2\n' + EXIT),
    ("getcwd with size 1 answered -ERANGE", "1 getcwd(0x40007ff8b0,1) = -1 errno=34\n" + EXIT),
    ("faccessat F_OK", '1 faccessat(AT_FDCWD,"in.bin",F_OK) = 0\n' + EXIT),
    ("faccessat2 F_OK with AT_EACCESS", '1 faccessat2(AT_FDCWD,"in.bin",F_OK,AT_EACCESS) = 0\n' + EXIT),
    ("fcntl F_SETFD", OPEN3 + "1 fcntl(3,F_SETFD,FD_CLOEXEC) = 0\n" + EXIT),
    ("fcntl F_SETFL that changes nothing", OPEN3 + "1 fcntl(3,F_SETFL,O_RDONLY|O_LARGEFILE) = 0\n" + EXIT),
    ("fcntl F_GETFL on a socket answering O_RDWR", SOCKET3 + "1 fcntl(3,F_GETFL) = 2\n" + EXIT),
    ("flock LOCK_UN on an open descriptor", OPEN3 + "1 flock(3,LOCK_UN) = 0\n" + EXIT),
    ("flock LOCK_EX on the one opener of a file", OPEN3 + "1 flock(3,LOCK_EX) = 0\n" + EXIT),
    ("getdents64 of a directory without room for an entry, -EINVAL",
     OPENDIR3 + "1 getdents64(3,0x40007ff8b0,16) = -1 errno=22\n" + EXIT),
    ("dup of a stdio channel", "1 dup(2) = 3\n" + EXIT),
    ("dup3 of a stdio channel to a low descriptor", "1 dup3(2,3,0) = 3\n" + EXIT),
    ("dup3 onto an open descriptor above NR_OPEN_DEFAULT", "1 dup3(2,70,0) = -1 errno=9\n" + EXIT),
    ("lseek on a file", OPEN3 + "1 lseek(3,0,SEEK_SET) = 0\n" + EXIT),
    ("ftruncate of an open descriptor", OPEN3 + "1 ftruncate(3,0) = 0\n" + EXIT),
    ("fsync of an open descriptor", OPEN3 + "1 fsync(3) = 0\n" + EXIT),
    ("pipe2 with no flags", "1 pipe2(0x40007ff8b0,0) = 0\n" + EXIT),
    ("readlinkat answered -EINVAL", '1 readlinkat(AT_FDCWD,"x",0x1000,64) = -1 errno=22\n' + EXIT),
    # -- reads and writes --------------------------------------------------------------------------------------------
    ("a write to standard output", "1 write(1,0x1000,2) = 2\n" + EXIT),
    ("a read of a file", OPEN3 + "1 read(3,0x1000,64) = 64\n" + EXIT),
    ("a write of 512 times rw_bytes_max at a buffer in range", "1 write(1,0x1000,67108864) = 67108864\n" + EXIT),
    ("a write of rw_bytes_max at a buffer past TASK_SIZE", "1 write(1,0x7fffffff0000,131072) = 131072\n" + EXIT),
    ("a read of standard input whose range runs past TASK_SIZE, -EFAULT",
     "1 read(0,0x1000,140737488355328) = -1 errno=14\n" + EXIT),
    ("a read of /dev/urandom that delivered the whole count",
     '1 openat(AT_FDCWD,"/dev/urandom",O_RDONLY|O_CLOEXEC) = 3\n1 read(3,0x1000,32) = 32\n' + EXIT),
    ("readv of two iovecs", OPEN3 + "1 readv(3,274886295728,2,0,0,0) = 8\n" + EXIT),
    ("writev with iovcnt above IOV_MAX answered -EINVAL", "1 writev(1,0x40007ff8b0,0x401) = -1 errno=22\n" + EXIT),
    ("pread64 at position 0", OPEN3 + "1 pread64(3,0x1000,64,0) = 64\n" + EXIT),
    ("getrandom of 4 bytes with flags 0", "1 getrandom(0x7f8eafbfd04c,4,0) = 4\n" + EXIT),
    ("getrandom with GRND_NONBLOCK", "1 getrandom(0x7f8eafbfd04c,4,1) = 4\n" + EXIT),
    ("getrandom above getrandom_small_max, a short read", "1 getrandom(0x7f8eafbfd04c,1024,0) = 512\n" + EXIT),
    ("getrandom above getrandom_small_max, -EINTR", "1 getrandom(0x7f8eafbfd04c,1024,0) = -1 errno=4\n" + EXIT),
    # -- signals, time and the rest ----------------------------------------------------------------------------------
    ("the isatty probe", "1 ioctl(1,TIOCGWINSZ,0x40007ff8b0) = -1 errno=25\n" + EXIT),
    ("ioctl TCGETS answered -ENOTTY", "1 ioctl(1,TCGETS,0x40007ff8b0) = -1 errno=25\n" + EXIT),
    ("clock_gettime on CLOCK_MONOTONIC, printed as a number", "1 clock_gettime(1,0x40007ff8b0) = 0\n" + EXIT),
    ("clock_gettime on CLOCK_REALTIME, printed by name", "1 clock_gettime(CLOCK_REALTIME,0x40007ff8b0) = 0\n" + EXIT),
    ("nanosleep answered 0", "1 nanosleep(274886295728,0,0,0,0,0) = 0\n" + EXIT),
    ("nanosleep answered -EINTR", "1 nanosleep(274886295728,274886295744,0,0,0,0) = -1 errno=4\n" + EXIT),
    ("gettimeofday with a NULL tz", "1 gettimeofday(0x40007ff8b0,NULL) = 0\n" + EXIT),
    ("rt_sigaction with act NULL", "1 rt_sigaction(SIGSEGV,NULL,NULL) = 0\n" + EXIT),
    ("rt_sigaction of a SIGINT handler", "1 rt_sigaction(SIGINT,0x40007ff8b0,NULL) = 0\n" + EXIT),
    ("rt_sigaction of a SIGSEGV handler answered -EINVAL (the sigsetsize qemu does not print)",
     "1 rt_sigaction(SIGSEGV,0x40007ff8b0,NULL) = -1 errno=22\n" + EXIT),
    ("rt_sigprocmask", "1 rt_sigprocmask(SIG_BLOCK,0x40007ff8b0,NULL,8) = 0\n" + EXIT),
    ("sigaltstack with a NULL old stack", "1 sigaltstack(0x40007ff8b0,NULL) = 0\n" + EXIT),
    ("prctl PR_CAPBSET_READ", "1 prctl(23,40,0,7517016,0,-8606760485637849041) = 1\n" + EXIT),
    ("prlimit64 reading RLIMIT_CORE",
     "1 prlimit64(0,RLIMIT_CORE,NULL,0x40007ff8b0) = 0 ({rlim_cur=0, rlim_max=0})\n" + EXIT),
    ("prlimit64 writing RLIMIT_CORE after a read",
     "1 prlimit64(0,RLIMIT_CORE,NULL,0x40007ff8b0) = 0 ({rlim_cur=0, rlim_max=0})\n"
     "1 prlimit64(0,RLIMIT_CORE,{rlim_cur=0, rlim_max=0},NULL) = 0\n" + EXIT),
    ("set_tid_address, then getpid with the same answer", TID + "1 getpid() = 1\n" + EXIT),
    ("a plain fork with no file open", "1 clone(SIGCHLD,0,0,0,0) = 1234\n" + EXIT),
    ("sched_getaffinity with a length the kernel refuses", "1 sched_getaffinity(0,12,0x40007ff8b0) = -1 errno=22\n"
     + EXIT),
    ("sched_setscheduler to SCHED_IDLE", "1 sched_setscheduler(0,5,0x40007ff8b0,0,0,0) = 0\n" + EXIT),
    ("sched_yield", "1 sched_yield() = 0\n" + EXIT),
    ("uname", "1 uname(0x40007ff8b0) = 0\n" + EXIT),
    ("getuid", "1 getuid() = 65534\n" + EXIT),
    ("eventfd2 with a bad flag, -EINVAL", "1 eventfd2(0,2) = -1 errno=22\n" + EXIT),
    ("epoll_create1 with a bad flag, -EINVAL", "1 epoll_create1(2) = -1 errno=22\n" + EXIT),
    ("epoll_ctl with an unreadable event, -EFAULT", "1 epoll_ctl(4,1,3,0,0,0) = -1 errno=14\n" + EXIT),
    ("epoll_pwait with an unreadable events array, -EFAULT", "1 epoll_pwait(4,0,1,0,0,8) = -1 errno=14\n" + EXIT),
    ("timerfd_create with a bad flag, -EINVAL", "1 timerfd_create(1,1,1,0,0,8) = -1 errno=22\n" + EXIT),
    ("pselect6 with a negative nfds, -EINVAL", "1 pselect6(-1,0,0,0,0,0) = -1 errno=22\n" + EXIT),
    ("ppoll with a bad timespec, -EINVAL", "1 ppoll((nil),0,0x7fae17bfd5e0,(nil)) = -1 errno=22\n" + EXIT),
    ("wait4(-1, WNOHANG) with no child, -ECHILD", "1 wait4(-1,0x40007ff8b0,1,NULL) = -1 errno=10\n" + EXIT),
    ("getgroups(0)", "1 getgroups(0,NULL) = 0\n" + EXIT),
    ("setgroups answered -EPERM", "1 setgroups(1,0x40007ff8b0) = -1 errno=1\n" + EXIT),
    # -- sockets -----------------------------------------------------------------------------------------------------
    ("socket AF_INET SOCK_STREAM", SOCKET3 + EXIT),
    ("socket of family 46, -EAFNOSUPPORT", "1 socket(46,SOCK_STREAM,IPPROTO_IP) = -1 errno=97\n" + EXIT),
    ("sendto with MSG_NOSIGNAL and no address", SOCKET3 + "1 sendto(3,0x1000,2,MSG_NOSIGNAL,NULL,0) = 2\n" + EXIT),
    ("connect on a socket answered -EAFNOSUPPORT", SOCKET3 + "1 connect(3,0x40007ff8b0,16) = -1 errno=97\n" + EXIT),
    ("getsockopt at a level the model refuses", SOCKET3 + "1 getsockopt(3,999,2,0x40007ff8b0,0x40007ff8c8) = -1 "
                                                          "errno=95\n" + EXIT),
    ("shutdown(SHUT_WR)", SOCKET3 + "1 shutdown(3,1,0,0,0,0) = 0\n" + EXIT),
    # -- the answers the model gives ---------------------------------------------------------------------------------
    ("a write to /dev/null that took the whole count",
     '1 openat(AT_FDCWD,"/dev/null",O_WRONLY|O_CREAT|O_TRUNC,0644) = 3\n1 write(3,0x1000,64) = 64\n' + EXIT),
    ("a short read of a file", OPEN3 + "1 read(3,0x1000,64) = 10\n" + EXIT),
    ("a short write to standard output", "1 write(1,0x1000,64) = 1\n" + EXIT),
    ("lseek SEEK_SET to 10", OPEN3 + "1 lseek(3,10,SEEK_SET) = 10\n" + EXIT),
    ("lseek SEEK_END on a file", OPEN3 + "1 lseek(3,0,SEEK_END) = 4096\n" + EXIT),
    ("setuid answered -EPERM", "1 setuid(0) = -1 errno=1\n" + EXIT),
    ("a fork, and the records of its child (Fork.v: the child is not executed by this model)",
     "1 clone(SIGCHLD,0,0,0,0) = 99\n99 getppid() = 1\n99 exit_group(0)\n" + EXIT),
    # -- the parser --------------------------------------------------------------------------------------------------
    ("two modeled records on one interleaved line", "1 write(1,0x1000,2)1 close(9) = -1 errno=9\n" + EXIT),
    ("a quoted path that looks like a record", '1 openat(AT_FDCWD,"12 evil(x",O_RDONLY) = 3\n' + EXIT),
    ("qemu's errno text after a return",
     "1 ioctl(1,TIOCGWINSZ,0x40007ff8b0) = -1 errno=25 (Inappropriate ioctl for device)\n" + EXIT),
    ("a struct printed after a return",
     OPEN3 + "1 read(3,0x1000,64) = 0 ({tv_sec = 1787258859,tv_nsec = 619631956})\n" + EXIT),
]

REJECT = [
    # -- by name: no arm in spec_table -------------------------------------------------------------------------------
    ("getppid (no arm 173)", "1 getppid() = 1\n" + EXIT),
    ("kill (no arm 129)", "1 kill(1234,SIGTERM) = 0\n" + EXIT),
    ("set_robust_list (no arm 99)", "1 set_robust_list(0x40007ff8b0,24) = 0\n" + EXIT),
    # -- the address space -------------------------------------------------------------------------------------------
    ("MAP_FIXED at address 0", "1 mmap(0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = 0\n"
     + EXIT),
    ("MAP_POPULATE",
     "1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE,-1,0) = 0x100000\n" + EXIT),
    ("an anonymous mmap with an aligned nonzero offset",
     "1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,4096) = 0x100000\n" + EXIT),
    ("an mmap grant that lands on a live mapping",
     MADVISE_GRANT + "1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x100000\n" + EXIT),
    ("an mmap grant that lands on the image",
     "1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x10000\n" + EXIT),
    ("an mmap that failed with -EEXIST",
     "1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = -1 errno=17\n" + EXIT),
    ("an rw MAP_FIXED ending one page above the smallest alloc_top",
     "1 mmap(0x7fff7f7ff000,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = 0x7fff7f7ff000\n"
     + EXIT),
    ("a MAP_FIXED that came back at another address",
     "1 mmap(0x100000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = 0x200000\n" + EXIT),
    ("a munmap of a free range above the smallest alloc_top", "1 munmap(0x7fff7f800000,4096) = 0\n" + EXIT),
    ("an interior partial munmap",
     "1 mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x100000\n"
     "1 munmap(0x100000,4096) = 0\n" + EXIT),
    ("a munmap of a tracked mapping that failed", MADVISE_GRANT + "1 munmap(0x100000,262144) = -1 errno=12\n" + EXIT),
    ("a file mapping with an aligned offset", "1 mmap(NULL,4096,PROT_EXEC,MAP_SHARED,3,4096) = 0x100000\n" + EXIT),
    ("mprotect to PROT_READ|PROT_EXEC", MADVISE_GRANT + "1 mprotect(0x100000,4096,PROT_READ|PROT_EXEC) = 0\n" + EXIT),
    ("mprotect of a range in no tracked mapping", "1 mprotect(0x100000,4096,PROT_READ|PROT_WRITE) = 0\n" + EXIT),
    ("mprotect of a read-write range that failed",
     MADVISE_GRANT + "1 mprotect(0x100000,4096,PROT_READ|PROT_WRITE) = -1 errno=12\n" + EXIT),
    ("mremap with MREMAP_MAYMOVE|MREMAP_FIXED",
     MADVISE_GRANT + "1 mremap(1048576,262144,524288,3,2097152,0) = 2097152\n" + EXIT),
    ("an mremap whose source is not one whole mapping",
     MADVISE_GRANT + "1 mremap(1048576,4096,8192,1,0,0) = 2097152\n" + EXIT),
    ("an mremap shrink that moved", MADVISE_GRANT + "1 mremap(1048576,262144,131072,1,0,0) = 2097152\n" + EXIT),
    ("an mremap grow onto a live mapping",
     MADVISE_GRANT + "1 mmap(0x200000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = 0x200000\n"
     "1 mremap(1048576,262144,524288,1,0,0) = 2097152\n" + EXIT),
    ("an mremap of a PROT_NONE reservation", GRANT_NONE + "1 mremap(1048576,65536,131072,1,0,0) = 1048576\n" + EXIT),
    ("a brk query that answered another address", "1 brk(NULL) = 0x100000\n1 brk(NULL) = 0x200000\n" + EXIT),
    ("a brk grow that answered neither the request nor the break",
     "1 brk(NULL) = 0x100000\n1 brk(0x102000) = 0x103000\n" + EXIT),
    ("a brk grow flush against a tracked mapping",
     "1 brk(NULL) = 0x100000\n"
     "1 mmap(0x102000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = 0x102000\n"
     "1 brk(0x102000) = 0x102000\n" + EXIT),
    # -- MAP_FIXED_NOREPLACE -----------------------------------------------------------------------------------------
    ("a made-up bit beside MAP_FIXED_NOREPLACE",
     "1 mmap(0x100000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE|0x800000,-1,0) = "
     "0x100000\n" + EXIT),
    ("MAP_FIXED_NOREPLACE with PROT_EXEC",
     "1 mmap(0x100000,4096,PROT_READ|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0) = 0x100000\n"
     + EXIT),
    ("MAP_FIXED_NOREPLACE with a nonzero offset",
     "1 mmap(0x100000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,4096) = 0x100000\n"
     + EXIT),
    ("-EEXIST on a range the replay calls free",
     "1 mmap(0x100000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0) = -1 errno=17 "
     "(File exists)\n" + EXIT),
    ("a grant over an occupied range",
     "1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x100000\n"
     "1 mmap(0x100000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0) = 0x100000\n"
     + EXIT),
    ("a grant placed elsewhere than the address",
     "1 mmap(0x100000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0) = 0x200000\n"
     + EXIT),
    # -- madvise -----------------------------------------------------------------------------------------------------
    ("DONTNEED over the tail a brk shrink freed",
     "1 brk(NULL) = 0x100000\n1 brk(0x102000) = 0x102000\n1 brk(0x101000) = 0x101000\n"
     "1 madvise(0x101000,4096,MADV_DONTNEED) = 0\n" + EXIT),
    ("MADV_NORMAL over a live grant", MADVISE_GRANT + "1 madvise(0x100000,4096,MADV_NORMAL) = 0\n" + EXIT),
    ("MADV_FREE over a live grant", MADVISE_GRANT + "1 madvise(0x100000,4096,MADV_FREE) = 0\n" + EXIT),
    ("an unaligned DONTNEED that returned 0", MADVISE_GRANT + "1 madvise(0x100001,4096,MADV_DONTNEED) = 0\n" + EXIT),
    ("DONTNEED over a range nothing tracked", "1 madvise(0x200000,4096,MADV_DONTNEED) = 0\n" + EXIT),
    ("DONTNEED across the end of its grant",
     "1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x100000\n"
     "1 madvise(0x100000,8192,MADV_DONTNEED) = -1 errno=12\n" + EXIT),
    ("DONTNEED across two adjacent grants",
     "1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x100000\n"
     "1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x101000\n"
     "1 madvise(0x100000,8192,MADV_DONTNEED) = 0\n" + EXIT),
    ("DONTNEED inside a live grant, -ENOMEM", MADVISE_GRANT + "1 madvise(0x100000,4096,MADV_DONTNEED) = -1 errno=12\n"
     + EXIT),
    ("DONTNEED over a PROT_NONE range", GRANT_NONE + "1 madvise(0x100000,4096,MADV_DONTNEED) = 0\n" + EXIT),
    # -- files and descriptors ---------------------------------------------------------------------------------------
    ("openat with O_WRONLY alone", '1 openat(AT_FDCWD,"/dev/null",O_WRONLY|O_LARGEFILE) = 3\n' + EXIT),
    ("a path of two components under /tmp",
     '1 openat(AT_FDCWD,"/tmp/tmp.TAN6NIi766/probe.bin",O_RDONLY|O_LARGEFILE) = 3\n' + EXIT),
    ("a relative path with a directory", '1 openat(AT_FDCWD,"build/probes/probe.bin",O_RDONLY) = 3\n' + EXIT),
    ("a read of a /tmp key never created", '1 openat(AT_FDCWD,"/tmp/x",O_RDONLY) = 3\n' + EXIT),
    ("/dev/urandom opened for writing", '1 openat(AT_FDCWD,"/dev/urandom",O_WRONLY|O_CREAT|O_TRUNC,0666) = 3\n'
     + EXIT),
    ("/etc/localtime opened", '1 openat(AT_FDCWD,"/etc/localtime",O_RDONLY) = 3\n' + EXIT),
    ("a successful O_DIRECTORY open of a name", '1 openat(AT_FDCWD,"dir",O_RDONLY|O_DIRECTORY) = 3\n' + EXIT),
    ("a create answered -ENOSPC", '1 openat(AT_FDCWD,"f",O_WRONLY|O_CREAT|O_TRUNC,0644) = -1 errno=28\n' + EXIT),
    ("unlinkat that removed a /tmp key never created", '1 unlinkat(AT_FDCWD,"/tmp/x.gz",0) = 0\n' + EXIT),
    ("unlinkat of two components under /tmp", '1 unlinkat(AT_FDCWD,"/tmp/a/b",0) = 0\n' + EXIT),
    ("unlinkat of a /tmp key with a descriptor open on it",
     '1 openat(AT_FDCWD,"/tmp/o.gz",O_WRONLY|O_CREAT|O_TRUNC,0600) = 3\n'
     '1 unlinkat(AT_FDCWD,"/tmp/o.gz",0) = 0\n' + EXIT),
    ("unlinkat relative to a dirfd", '1 unlinkat(3,"x.gz",0) = 0\n' + EXIT),
    ("fstat of standard output", "1 fstat(1,0x40007ff8b0) = 0\n" + EXIT),
    ("fstat of a directory", OPENDIR3 + "1 fstat(3,0x40007ff8b0) = 0\n" + EXIT),
    ("fstat of a descriptor the run never opened that succeeded", "1 fstat(7,0x40007ff8b0) = 0\n" + EXIT),
    ("newfstatat of a path that resolved", '1 newfstatat(AT_FDCWD,"in.bin",0x40007ff8b0,0) = 0\n' + EXIT),
    ("newfstatat with AT_NO_AUTOMOUNT", '1 newfstatat(AT_FDCWD,"f",0x40007ff8b0,AT_NO_AUTOMOUNT) = 0\n' + EXIT),
    ("getcwd that succeeded", "1 getcwd(0x40007ff8b0,4096) = 5\n" + EXIT),
    ("faccessat R_OK", '1 faccessat(AT_FDCWD,"in.bin",R_OK) = 0\n' + EXIT),
    ("faccessat2 with AT_EMPTY_PATH", '1 faccessat2(AT_FDCWD,"",F_OK,AT_EMPTY_PATH) = 0\n' + EXIT),
    ("fcntl F_GETFL on a plain file", OPEN3 + "1 fcntl(3,F_GETFL) = 0\n" + EXIT),
    ("fcntl F_SETFL turning on O_NONBLOCK", OPEN3 + "1 fcntl(3,F_SETFL,O_RDONLY|O_NONBLOCK) = 0\n" + EXIT),
    ("fcntl F_SETFL on standard input", "1 fcntl(0,F_SETFL,O_RDONLY) = 0\n" + EXIT),
    ("fcntl F_SETFD on a descriptor the run never opened", "1 fcntl(7,F_SETFD,FD_CLOEXEC) = 0\n" + EXIT),
    ("flock LOCK_EX on a stdio channel", "1 flock(1,LOCK_EX) = 0\n" + EXIT),
    ("flock LOCK_EX while two descriptors name the file",
     OPEN3 + '1 openat(AT_FDCWD,"in.bin",O_RDONLY|O_LARGEFILE) = 4\n1 flock(3,LOCK_EX) = 0\n' + EXIT),
    ("getdents64 of a directory with room", OPENDIR3 + "1 getdents64(3,0x40007ff8b0,2048) = 120\n" + EXIT),
    ("getdents64 of a file answered -EINVAL", OPEN3 + "1 getdents64(3,0x40007ff8b0,16) = -1 errno=22\n" + EXIT),
    ("dup of a file descriptor", OPEN3 + "1 dup(3) = 4\n" + EXIT),
    ("dup3 onto a free descriptor above NR_OPEN_DEFAULT", "1 dup3(2,70,0) = 70\n" + EXIT),
    ("dup3 with a flag outside O_CLOEXEC that succeeded", "1 dup3(2,3,4000) = 3\n" + EXIT),
    ("dup3 of a descriptor onto itself that succeeded", "1 dup3(2,2,0) = 2\n" + EXIT),
    ("lseek on a directory", OPENDIR3 + "1 lseek(3,0,SEEK_SET) = 0\n" + EXIT),
    ("lseek with SEEK_HOLE", OPEN3 + "1 lseek(3,0,SEEK_HOLE) = 0\n" + EXIT),
    ("ftruncate of a descriptor the run never opened that succeeded", "1 ftruncate(7,0) = 0\n" + EXIT),
    ("pipe2 with O_CLOEXEC", "1 pipe2(0x40007ff8b0,0x80000) = 0\n" + EXIT),
    ("readlinkat that succeeded", '1 readlinkat(AT_FDCWD,"/proc/self/exe",0x40007ff8b0,4096) = 12\n' + EXIT),
    ("ioctl FIONREAD", "1 ioctl(1,FIONREAD,0x40007ff8b0) = 0\n" + EXIT),
    ("ioctl on /dev/urandom", '1 openat(AT_FDCWD,"/dev/urandom",O_RDONLY) = 3\n'
                              "1 ioctl(3,TIOCGWINSZ,0x40007ff8b0) = -1 errno=25\n" + EXIT),
    ("a terminal ioctl that succeeded", "1 ioctl(1,TIOCGWINSZ,0x40007ff8b0) = 0\n" + EXIT),
    # -- reads and writes --------------------------------------------------------------------------------------------
    ("a write on standard input", "1 write(0,0x1000,2) = 2\n" + EXIT),
    ("a read of standard output", "1 read(1,0x1000,2) = 2\n" + EXIT),
    ("a read of a write-only file", '1 openat(AT_FDCWD,"f",O_WRONLY|O_CREAT|O_TRUNC,0644) = 3\n'
                                    "1 read(3,0x1000,64) = 64\n" + EXIT),
    ("a write on a descriptor the run never opened that succeeded", "1 write(7,0x1000,2) = 2\n" + EXIT),
    ("a read of a descriptor the run never opened that succeeded", "1 read(7,0x1000,64) = 64\n" + EXIT),
    ("a short read of /dev/urandom", '1 openat(AT_FDCWD,"/dev/urandom",O_RDONLY) = 3\n'
                                     "1 read(3,0x1000,32) = 16\n" + EXIT),
    ("readv of /dev/urandom that delivered bytes",
     '1 openat(AT_FDCWD,"/dev/urandom",O_RDONLY) = 3\n1 readv(3,274886295728,2,0,0,0) = 32\n' + EXIT),
    ("readv with iovcnt 9", OPEN3 + "1 readv(3,274886295728,9,0,0,0) = 8\n" + EXIT),
    ("writev with iovcnt above IOV_MAX that succeeded", "1 writev(1,0x40007ff8b0,0x401) = 4\n" + EXIT),
    ("pwrite64 on an append file", '1 openat(AT_FDCWD,"log",O_WRONLY|O_CREAT|O_APPEND,0644) = 3\n'
                                   "1 pwrite64(3,0x1000,64,0) = 64\n" + EXIT),
    ("getrandom with GRND_RANDOM", "1 getrandom(0x7f8eafbfd04c,4,2) = 4\n" + EXIT),
    ("getrandom of rw_bytes_max + 1 bytes", "1 getrandom(0x7f8eafbfd04c,131073,0) = 131073\n" + EXIT),
    ("a short getrandom at or below getrandom_small_max", "1 getrandom(0x7f8eafbfd04c,256,0) = 128\n" + EXIT),
    ("getrandom of 4 bytes answered -EINTR", "1 getrandom(0x7f8eafbfd04c,4,0) = -1 errno=4\n" + EXIT),
    # -- signals, time and the rest ----------------------------------------------------------------------------------
    ("clock_gettime on CLOCK_TAI", "1 clock_gettime(CLOCK_TAI,0x40007ff8b0) = 0\n" + EXIT),
    ("clock_gettime answered -EFAULT", "1 clock_gettime(1,0x40007ff8b0) = -1 errno=14\n" + EXIT),
    ("nanosleep answered -EFAULT", "1 nanosleep(274886295728,0,0,0,0,0) = -1 errno=14\n" + EXIT),
    ("gettimeofday with a timezone", "1 gettimeofday(0x40007ff8b0,0x40007ff8c8) = 0\n" + EXIT),
    ("rt_sigaction of a SIGSEGV handler", "1 rt_sigaction(SIGSEGV,0x40007ff8b0,NULL) = 0\n" + EXIT),
    ("rt_sigaction with a non-NULL old action", "1 rt_sigaction(SIGINT,0x40007ff8b0,0x40007ff8c8) = 0\n" + EXIT),
    ("rt_sigprocmask with a sigsetsize other than 8 that succeeded",
     "1 rt_sigprocmask(SIG_BLOCK,0x40007ff8b0,NULL,16) = 0\n" + EXIT),
    ("sigaltstack with an old-stack pointer", "1 sigaltstack(0x40007ff8b0,0x40007ff8c8) = 0\n" + EXIT),
    ("a second sigaltstack after an install",
     "1 sigaltstack(0x40007ff8b0,NULL) = 0\n1 sigaltstack(0x40007ff8c8,NULL) = 0\n" + EXIT),
    ("prctl PR_SET_NAME", "1 prctl(15,0x40007ff8b0,0,0,0,0) = 0\n" + EXIT),
    ("prlimit64 on RLIMIT_STACK", "1 prlimit64(0,RLIMIT_STACK,NULL,0x40007ff8b0) = 0\n" + EXIT),
    ("prlimit64 with both pointers NULL", "1 prlimit64(0,RLIMIT_CORE,NULL,NULL) = 0\n" + EXIT),
    ("prlimit64 writing before any read",
     "1 prlimit64(0,RLIMIT_CORE,{rlim_cur=0, rlim_max=0},NULL) = 0\n" + EXIT),
    ("prlimit64 writing a soft limit above the hard limit",
     "1 prlimit64(0,RLIMIT_CORE,NULL,0x40007ff8b0) = 0\n"
     "1 prlimit64(0,RLIMIT_CORE,{rlim_cur=8192, rlim_max=4096},NULL) = 0\n" + EXIT),
    ("a task id that came back twice with different answers", TID + "1 getpid() = 7\n" + EXIT),
    ("a thread start",
     "1 clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|"
     "CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID,0x100000,0x200000,0x300000,0x400000) = 1234\n" + EXIT),
    ("a fork while a file is open", OPEN3 + "1 clone(SIGCHLD,0,0,0,0) = 1234\n" + EXIT),
    ("a fork while a socket is open", SOCKET3 + "1 clone(SIGCHLD,0,0,0,0) = 1234\n" + EXIT),
    ("a fork after a pipe2", "1 pipe2(0x40007ff8b0,0) = 0\n1 clone(SIGCHLD,0,0,0,0) = 1234\n" + EXIT),
    ("clone3 with a size other than 88", "1 clone3(0x40007ff8b0,64,0,0,0,0) = 1234\n" + EXIT),
    ("sched_getaffinity that succeeded", "1 sched_getaffinity(0,128,0x40007ff8b0) = 8\n" + EXIT),
    ("sched_setscheduler to SCHED_FIFO that succeeded", "1 sched_setscheduler(0,1,0x40007ff8b0,0,0,0) = 0\n" + EXIT),
    ("sched_setscheduler of another pid", "1 sched_setscheduler(42,5,0x40007ff8b0,0,0,0) = 0\n" + EXIT),
    ("getgroups delivering a list", "1 getgroups(32,0x40007ff8b0) = 3\n" + EXIT),
    ("setgroups that succeeded", "1 setgroups(0,NULL) = 0\n" + EXIT),
    ("wait4 for a pid that succeeded", "1 wait4(1234,0x40007ff8b0,0,NULL) = 1234\n" + EXIT),
    ("eventfd2 with EFD_SEMAPHORE", "1 eventfd2(0,1) = 3\n" + EXIT),
    ("epoll_create1(0)", "1 epoll_create1(0) = 3\n" + EXIT),
    ("epoll_ctl that succeeded", "1 epoll_ctl(4,1,3,274886295552,0,0) = 0\n" + EXIT),
    ("epoll_pwait that returned an event", "1 epoll_pwait(4,274886295552,64,-1,0,8) = 1\n" + EXIT),
    ("timerfd_create that succeeded", "1 timerfd_create(1,524288,1,0,0,8) = 5\n" + EXIT),
    ("pselect6 without a timeout that returned 0", "1 pselect6(0,0,0,0,0,0) = 0\n" + EXIT),
    ("ppoll with nfds above 30", "1 ppoll(0x7fae17bfd5e0,31,(nil),(nil)) = 0\n" + EXIT),
    # -- sockets -----------------------------------------------------------------------------------------------------
    ("socket PF_UNIX", "1 socket(PF_UNIX,SOCK_STREAM,IPPROTO_IP) = 3\n" + EXIT),
    ("socket AF_INET with SOCK_NONBLOCK", "1 socket(PF_INET,SOCK_STREAM|SOCK_NONBLOCK,IPPROTO_IP) = 3\n" + EXIT),
    ("socketpair AF_INET stream that succeeded", "1 socketpair(PF_INET,SOCK_STREAM,IPPROTO_IP,0x40007ff8b0) = 0\n"
     + EXIT),
    ("accept with an address pointer", SOCKET3 + "1 accept(3,0x40007ff8b0,0x40007ff8c8) = 4\n" + EXIT),
    ("connect to an address that resolved", SOCKET3 + '1 connect(3,{sin_family=AF_INET,sin_port=htons(53),'
     'sin_addr=inet_addr("127.0.0.1")},16) = 0\n' + EXIT),
    ("connect with an AF_UNSPEC address on a socket a bind has used",
     SOCKET3 + "1 bind(3,{sa_family=0, sa_data={00, 00}},16) = 0\n"
     "1 connect(3,{sa_family=0, sa_data={00, 00}},16) = 0\n" + EXIT),
    ("connect on a file", OPEN3 + "1 connect(3,0x40007ff8b0,16) = -1 errno=97\n" + EXIT),
    ("recvfrom that received bytes", SOCKET3 + "1 recvfrom(3,0x1000,64,0,NULL,NULL) = 64\n" + EXIT),
    ("setsockopt that succeeded", SOCKET3 + "1 setsockopt(3,1,2,0x40007ff8b0,4) = 0\n" + EXIT),
    ("sendto with flags 0", SOCKET3 + "1 sendto(3,0x1000,2,0,NULL,0) = 2\n" + EXIT),
    ("sendto on a file", OPEN3 + "1 sendto(3,0x1000,2,MSG_NOSIGNAL,NULL,0) = 2\n" + EXIT),
    ("a write on a socket", SOCKET3 + "1 write(3,0x1000,2) = 2\n" + EXIT),
    ("shutdown(SHUT_RD) that succeeded", SOCKET3 + "1 shutdown(3,0,0,0,0,0) = 0\n" + EXIT),
    # -- answers the model does not give -----------------------------------------------------------------------------
    ("a read of a file that returned more than its count", OPEN3 + "1 read(3,0x1000,4) = 8\n" + EXIT),
    ("a read of a file answered -EIO", OPEN3 + "1 read(3,0x1000,64) = -1 errno=5\n" + EXIT),
    ("a read of a fresh socket that delivered bytes", SOCKET3 + "1 read(3,0x1000,64) = 64\n" + EXIT),
    ("a write to standard output that returned more than its count", "1 write(1,0x1000,2) = 3\n" + EXIT),
    ("a write of 2 bytes to standard output that returned 0", "1 write(1,0x1000,2) = 0\n" + EXIT),
    ("a write to standard output answered -EIO", "1 write(1,0x1000,2) = -1 errno=5\n" + EXIT),
    ("a short write to /dev/null",
     '1 openat(AT_FDCWD,"/dev/null",O_WRONLY|O_CREAT|O_TRUNC,0644) = 3\n1 write(3,0x1000,64) = 32\n' + EXIT),
    ("readv of a write-only file", '1 openat(AT_FDCWD,"f",O_WRONLY|O_CREAT|O_TRUNC,0644) = 3\n'
                                   "1 readv(3,274886295728,2,0,0,0) = 8\n" + EXIT),
    ("writev to standard input", "1 writev(0,0x40007ff8b0,0x2) = 4\n" + EXIT),
    ("writev to standard output answered -EIO", "1 writev(1,0x40007ff8b0,0x2) = -1 errno=5\n" + EXIT),
    ("pread64 at a negative position that succeeded", OPEN3 + "1 pread64(3,0x1000,64,-1) = 64\n" + EXIT),
    ("pread64 of standard input that succeeded", "1 pread64(0,0x1000,64,0) = 64\n" + EXIT),
    ("pread64 of a file that returned more than its count", OPEN3 + "1 pread64(3,0x1000,64,0) = 65\n" + EXIT),
    ("pwrite64 at a negative position that succeeded", '1 openat(AT_FDCWD,"f",O_WRONLY|O_CREAT|O_TRUNC,0644) = 3\n'
                                                       "1 pwrite64(3,0x1000,64,-1) = 64\n" + EXIT),
    ("pwrite64 to a read-only file", OPEN3 + "1 pwrite64(3,0x1000,64,0) = 64\n" + EXIT),
    ("lseek SEEK_SET that landed elsewhere", OPEN3 + "1 lseek(3,10,SEEK_SET) = 11\n" + EXIT),
    ("lseek with whence 9 that succeeded", OPEN3 + "1 lseek(3,0,9) = 0\n" + EXIT),
    ("lseek on standard input that succeeded", "1 lseek(0,0,SEEK_SET) = 0\n" + EXIT),
    ("lseek on a file answered -EIO", OPEN3 + "1 lseek(3,0,SEEK_CUR) = -1 errno=5\n" + EXIT),
    ("fstat of a file that returned 1", OPEN3 + "1 fstat(3,0x40007ff8b0) = 1\n" + EXIT),
    ("fstat of a file answered -EIO", OPEN3 + "1 fstat(3,0x40007ff8b0) = -1 errno=5\n" + EXIT),
    ("fcntl F_SETFD that returned 1", OPEN3 + "1 fcntl(3,F_SETFD,FD_CLOEXEC) = 1\n" + EXIT),
    ("fcntl F_SETFD on an open file answered -EBADF", OPEN3 + "1 fcntl(3,F_SETFD,FD_CLOEXEC) = -1 errno=9\n" + EXIT),
    ("fcntl F_SETFL that changes nothing answered -EINVAL",
     OPEN3 + "1 fcntl(3,F_SETFL,O_RDONLY|O_LARGEFILE) = -1 errno=22\n" + EXIT),
    ("flock LOCK_UN that returned 3", OPEN3 + "1 flock(3,LOCK_UN) = 3\n" + EXIT),
    ("flock LOCK_MAND answered -EBADF", "1 flock(9,LOCK_MAND) = -1 errno=9\n" + EXIT),
    ("flock LOCK_EX of the one opener answered -EAGAIN", OPEN3 + "1 flock(3,LOCK_EX) = -1 errno=11\n" + EXIT),
    ("sched_yield that returned 1", "1 sched_yield() = 1\n" + EXIT),
    ("uname answered -EPERM", "1 uname(0x40007ff8b0) = -1 errno=1\n" + EXIT),
    ("setuid that returned 5", "1 setuid(0) = 5\n" + EXIT),
    ("setresgid answered -EAGAIN", "1 setresgid(0,0,0) = -1 errno=11\n" + EXIT),
    ("close of an open file that returned 5", OPEN3 + "1 close(3) = 5\n" + EXIT),
    ("close of an open file answered -EBADF", OPEN3 + "1 close(3) = -1 errno=9\n" + EXIT),
    ("a fork that returned 0", "1 clone(SIGCHLD,0,0,0,0) = 0\n" + EXIT),
    ("a fork that returned the task's own id", TID + "1 clone(SIGCHLD,0,0,0,0) = 1\n" + EXIT),
    ("a task id of 2^22", "1 set_tid_address(0x64dbf0) = 4194304\n" + EXIT),
    ("a second setsid that succeeded", "1 setsid() = 1\n1 setsid() = 1\n" + EXIT),
    # -- the parser ----------------------------------------------------------------------------------------------
    ("an unmodeled call behind a blocked modeled one", OPEN3 + "1 read(3,0x1000,64)1 getppid() = 1\n = 64\n" + EXIT),
    ("an unmodeled call behind a modeled one", "1 write(1,0x1000,2)1 kill(1234,SIGTERM) = 0\n" + EXIT),
    ("an Unknown syscall line after an open record", "1 write(1,0x1000,2)1 Unknown syscall 173\n" + EXIT),
    ("a partial munmap whose return the blocked mmap before it would take",
     "1 mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x100000\n"
     "1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0)1 munmap(0x100000,4096) = 0\n" + EXIT),
]
NAME_REJECTS = 3       # the first REJECT plants are about the name; the rest are about a shape or an answer


# ---------------------------------------------------------------------------------------------------------------------
# The plants, each way
# ---------------------------------------------------------------------------------------------------------------------
@needs_model
@pytest.mark.parametrize("label,text", ACCEPT, ids=[label for label, _ in ACCEPT])
def test_accepted(model, image, label, text):
    result = check(model, image, text)
    assert result["verdict"] == "pass", result["unmodeled"]
    assert result["exited"] and result["host_log"] == "present"


@needs_model
@pytest.mark.parametrize("label,text", REJECT, ids=[label for label, _ in REJECT])
def test_refused(model, image, label, text):
    result = check(model, image, text)
    assert result["verdict"] == "fail"
    assert result["unmodeled"], "a refusal must name a call"


@needs_model
def test_shape_plants_are_modeled_by_name(model):
    # A shape plant whose call is not even an arm would be refused without the shape rule being read. The plants that
    # hide an unmodeled call on an interleaved line do so on purpose.
    for label, text in REJECT[NAME_REJECTS:]:
        lines = text.splitlines()
        if any(len(list(S.split_records(line))) > 1 for line in lines):
            continue
        names = {name for line in lines for _, name, _, _, _ in S.split_records(line)}
        assert names <= model.names, (label, sorted(names - model.names))
    for label, text in REJECT[:NAME_REJECTS]:
        assert not {name for line in text.splitlines() for _, name, _, _, _ in S.split_records(line)} <= model.names


def test_interleaved_plants_are_really_interleaved():
    # Tidying an interleaved plant onto two lines would keep its verdict and stop testing the splitter.
    def multi(plants):
        return [label for label, text in plants
                if any(len(list(S.split_records(line))) > 1 for line in text.splitlines())]
    assert len(multi(ACCEPT)) >= 1 and len(multi(REJECT)) >= 3


@needs_model
def test_a_truncated_trace_fails_only_with_require_exit(model, image):
    for text in ("", "1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x100000"):
        result = check(model, image, text)
        assert (result["verdict"], result["exited"], result["unmodeled"]) == ("fail", False, [])
        assert check(model, image, text, require_exit=False)["verdict"] == "pass"


# ---------------------------------------------------------------------------------------------------------------------
# The host-call log
# ---------------------------------------------------------------------------------------------------------------------
def test_host_log_lines():
    log = S.HostLog("exec\n"
                    "mmap 2203096121344 1008fff7000 6fff0001000 3 100022 ffffffffffffffff 0\n"
                    "munmap 0 2acaabe6f000 1000 0 0 0 0\n"
                    "read -14 5 1000 40 0 0 0\n"
                    "  getcwd 5 40007ff8b0 1 0 0 0 0  \n"
                    "\nnonsense\nmmap 0 1 2 3\nfutex 0 1 2 3 4 5 6\n")
    assert log.started and log.given
    assert [row[0] for row in log.lines] == ["mmap", "munmap", "read", "getcwd"]
    assert log.lines[0][1] == 2203096121344 and log.lines[2][1] == -14
    assert not S.HostLog("mmap 0 1 2 3 4 5 6\n").started
    assert not S.HostLog(None).given and S.HostLog(None).lines == []


def test_host_log_take_is_first_unused_and_needs_agreement():
    log = S.HostLog("exec\nmmap 100000 0 100000000 3 22 ffffffffffffffff 0\n"
                    "mmap 200000 0 200000000 3 22 ffffffffffffffff 0\n"
                    "mmap 300000 0 1000 3 22 ffffffffffffffff 0\n")
    # Two lines agree with a printed length of 0 and disagree on the full one: nothing is taken.
    assert log.take("mmap", {1: S.Arg.cut(0)}, (1,)) is None
    # With the offset keyed as well, each of the first two is still a candidate; the third disagrees on the length.
    assert log.take("mmap", {1: S.Arg.cut(0x1000)}, (1,)) == {1: 0x1000}
    assert log.take("mmap", {1: S.Arg.cut(0x1000)}, (1,)) is None, "the line is used up"
    assert log.take("munmap", {}, (1,)) is None


@needs_model
def test_a_missing_host_log_decides_nothing(model, image):
    quiet = "1 write(1,0x1000,2) = 2\n" + EXIT
    for lengths in (None, "", "mmap 0 1 2 3 4 5 6\n"):
        result = S.check_trace(model, quiet, stance="off", binary=image, lengths=lengths)
        assert (result["verdict"], result["host_log"]) == ("undecided", "missing"), lengths
    assert check(model, image, quiet)["verdict"] == "pass"
    # An unmodeled call is a finding whatever the log says, and check_binaries reads host_log as well.
    loud = S.check_trace(model, "1 getppid() = 1\n" + EXIT, stance="off", binary=image, lengths=None)
    assert (loud["verdict"], loud["host_log"]) == ("fail", "missing")
    assert [u["call"] for u in loud["unmodeled"]] == ["getppid"]


@needs_model
@pytest.mark.parametrize("line,wanted", [
    # Each of these is a call the model refuses at a larger register, and accepts at the printed value.
    ("1 write(1,0x1000,-1) = -1 errno=14", "the write's buffer and count"),
    ("1 read(0,0x1000,8) = 8", "the read's buffer and count"),
    ("1 getcwd(0x40007ff8b0,1) = -1 errno=34", "the getcwd size"),
    ("1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x100000", "the mmap length"),
    ("1 munmap(0x8000000000,4096) = 0", "the munmap length"),
    ("1 mprotect(0x100000,4096,PROT_READ|PROT_WRITE) = 0", "the mprotect length"),
    ("1 madvise(0x100000,4096,MADV_DONTNEED) = 0", "the madvise length"),
])
def test_an_argument_qemu_cut_is_not_read_as_a_whole_register(model, image, line, wanted):
    # With no host line for the call, the register's high bits are unknown and the checker declines.
    why = one_undecided(check(model, image, line + "\n" + EXIT, lengths="exec\n"))
    assert wanted in why and "larger register" in why


@needs_model
@pytest.mark.parametrize("line,verdict", [
    ("1 write(1,0x1000,2) = 2", "pass"),
    ("1 write(1,0x1000,-1) = -1 errno=14", "fail"),          # the real count is 2^32 - 1, past rw_bytes_max
    ("1 read(0,0x1000,-1) = -1 errno=14", "pass"),           # a channel read: access_okb is false either way
    ("1 getcwd(0x40007ff8b0,-1) = 5", "fail"),               # the real size is above 1
    ("1 getrandom(0x7f8eafbfd04c,-1,0) = 4", "fail"),        # the real buflen is above rw_bytes_max
])
def test_the_host_log_gives_the_full_register(model, image, line, verdict):
    text = line + "\n" + EXIT
    assert check(model, image, text)["verdict"] == verdict, whys(check(model, image, text))


@needs_model
def test_a_cut_count_that_the_host_log_pins_as_huge(model, image):
    # qemu prints a count of 2^32 + 8 as 8; the model's write arm declines it, and the trace alone cannot see that.
    text = "1 write(1,0x7fffffff0000,8) = 8\n" + EXIT
    assert check(model, image, text)["verdict"] == "pass"
    log = "exec\nwrite 8 1 7fffffff0000 100000008 0 0 0\n"
    why = one_why(check(model, image, text, lengths=log), "write")
    assert "modeled_rw_range" in why


@needs_model
def test_a_sendto_count_is_printed_whole_and_read_unsigned(model, image):
    assert check(model, image, SOCKET3 + "1 sendto(3,0x1000,2,MSG_NOSIGNAL,NULL,0) = 2\n" + EXIT)["verdict"] == "pass"
    why = one_why(check(model, image, SOCKET3 + "1 sendto(3,0x1000,-1,MSG_NOSIGNAL,NULL,0) = 2\n" + EXIT), "sendto")
    assert "rw_bytes_max" in why and "unsigned" in why


@needs_model
def test_a_struct_printed_for_a_pointer_is_not_null(model, image):
    # qemu prints a readable timespec and socket address in place of the pointer (print_timespec, print_sockaddr).
    timeout = ("1 futex(0x52b0e0,FUTEX_PRIVATE_FLAG|FUTEX_WAIT,2,{tv_sec = 0,tv_nsec = 1000},NULL,0) = -1 errno=11\n"
               + EXIT)
    assert "with a timeout" in one_why(check(model, image, timeout), "futex")
    address = (SOCKET3 + "1 sendto(3,0x1000,2,MSG_NOSIGNAL,{sin_family=AF_INET,sin_port=htons(53),"
               'sin_addr=inet_addr("127.0.0.1")},16) = 2\n' + EXIT)
    assert "destination address" in one_why(check(model, image, address), "sendto")
    for text in ("NULL", "(nil)", "0", "0x0"):
        assert S.is_null(text), text
    assert not S.is_null("{tv_sec = 0,tv_nsec = 0}") and not S.is_null("0x1000")


@needs_model
def test_the_futex_operation_is_the_sign_extension_of_what_qemu_prints(model, image):
    # futex_spec compares the whole register; qemu, the kernel and qemu's do_futex all read the operation as an int,
    # so the register is the sign extension of the 32 bits qemu printed (the RISC-V calling convention).
    for line in ("1 futex(0x52b0e0,FUTEX_PRIVATE_FLAG|FUTEX_WAKE,2147483647,NULL,0,0) = 0",
                 "1 futex(0x52b0e0,FUTEX_PRIVATE_FLAG|FUTEX_WAIT,2,NULL,0,0) = -1 errno=11"):
        assert check(model, image, line + "\n" + EXIT)["verdict"] == "pass"
    for line in ("1 futex(0x52b0e0,FUTEX_WAKE,1,NULL,0,0) = 0",                 # no FUTEX_PRIVATE_FLAG
                 "1 futex(0x52b0e0,0x80000081,1,NULL,0,0) = 0"):                # the sign bit: a far larger register
        assert "unmodeled" in one_why(check(model, image, line + "\n" + EXIT), "futex")
    assert S.Arg.sext(0x80000081).v == (1 << 64) - (1 << 32) + 0x80000081
    assert S.Arg.sext(129).v == 129 and S.Arg.sext(-1).v == (1 << 64) - 1
    assert S.Arg.sext(129).exact


# ---------------------------------------------------------------------------------------------------------------------
# The descriptor table
# ---------------------------------------------------------------------------------------------------------------------
@needs_model
def test_the_table_starts_with_the_three_channels(model, image):
    assert check(model, image, "1 write(1,0x1000,2) = 2\n1 write(2,0x1000,2) = 2\n" + EXIT)["verdict"] == "pass"
    assert "channel 0" in one_why(check(model, image, "1 write(0,0x1000,2) = 2\n" + EXIT), "write")


@needs_model
def test_a_channel_closed_and_reopened_is_a_file(model, image):
    # The kind follows the table, not the number: fstat of a channel is unmodeled, of a file it is answered.
    text = '1 close(1) = 0\n1 openat(AT_FDCWD,"out.bin",O_RDONLY|O_LARGEFILE) = 1\n1 fstat(1,0x40007ff8b0) = 0\n'
    assert check(model, image, text + EXIT)["verdict"] == "pass"
    assert "channel" in one_why(check(model, image, "1 fstat(1,0x40007ff8b0) = 0\n" + EXIT), "fstat")


@needs_model
def test_an_open_of_dot_is_a_directory(model, image):
    for path in (".", ".."):
        text = f'1 openat(AT_FDCWD,"{path}",O_RDONLY|O_LARGEFILE) = 3\n1 fstat(3,0x40007ff8b0) = 0\n' + EXIT
        assert "directory" in one_why(check(model, image, text), "fstat")
    assert check(model, image, OPEN3 + "1 fstat(3,0x40007ff8b0) = 0\n" + EXIT)["verdict"] == "pass"


@needs_model
@pytest.mark.parametrize("copy", ["1 dup(0) = 3\n", "1 dup3(0,3,0) = 3\n"])
def test_a_copy_of_a_channel_is_a_channel(model, image, copy):
    for call, needle in (("fstat(3,0x40007ff8b0) = 0", "channel"),
                         ("flock(3,LOCK_EX) = 0", "channel"),
                         ("fcntl(3,F_SETFL,O_RDONLY) = 0", "channel")):
        assert needle in one_why(check(model, image, copy + "1 " + call + "\n" + EXIT))


@needs_model
def test_dup3_overwrites_the_new_descriptor(model, image):
    # fd 3 is a file, then channel 2's entry takes it: fstat of a channel is unmodeled.
    text = OPEN3 + "1 dup3(2,3,0) = 3\n1 fstat(3,0x40007ff8b0) = 0\n" + EXIT
    assert "channel" in one_why(check(model, image, text), "fstat")


@needs_model
@pytest.mark.parametrize("call", ["fstat(5,0x40007ff8b0) = 0", "flock(5,LOCK_EX) = 0", "dup(5) = 6",
                                  "fcntl(5,F_SETFL,O_RDONLY) = 0", "read(5,0x1000,64) = 64",
                                  "sendto(5,0x1000,2,MSG_NOSIGNAL,NULL,0) = 2"])
def test_after_a_pipe2_an_untracked_descriptor_declines(model, image, call):
    text = "1 pipe2(0x40007ff8b0,0) = 0\n1 " + call + "\n" + EXIT
    assert "pipe2 may have made" in one_undecided(check(model, image, text))
    # Without the pipe2 the model's table has no such descriptor, and only -EBADF is an answer.
    assert "never opened" in one_why(check(model, image, "1 " + call + "\n" + EXIT))
    bad = "1 pipe2(0x40007ff8b0,0) = 0\n1 " + call.split(" = ")[0] + " = -1 errno=9\n" + EXIT
    assert check(model, image, bad)["verdict"] == "pass"


@needs_model
def test_prlimit64_carries_the_hard_limit_from_the_read(model, image):
    read = "1 prlimit64(0,RLIMIT_CORE,NULL,0x40007ff8b0) = 0 ({rlim_cur=1, rlim_max=4096})\n"
    same = read + "1 prlimit64(0,RLIMIT_CORE,{rlim_cur=2, rlim_max=4096},NULL) = 0\n" + EXIT
    assert check(model, image, same)["verdict"] == "pass"
    changed = read + "1 prlimit64(0,RLIMIT_CORE,{rlim_cur=2, rlim_max=8192},NULL) = 0\n" + EXIT
    assert "changed rlim_max" in one_why(check(model, image, changed), "prlimit64")
    omitted = "1 prlimit64(0,RLIMIT_CORE,NULL,0x40007ff8b0) = 0\n" \
              "1 prlimit64(0,RLIMIT_CORE,{rlim_cur=2, rlim_max=4096},NULL) = 0\n" + EXIT
    result = check(model, image, omitted)
    assert result["verdict"] == "undecided" and result["unmodeled"] == []
    assert [u["call"] for u in result["undecided"]] == ["prlimit64", "prlimit64"]
    assert "did not show rlim_max" in result["undecided"][1]["why"]


@needs_model
def test_a_write_to_qemus_own_log_descriptor_is_refused(model, image):
    # qemu holds the -D log on a descriptor of its own, which the model's table does not have.
    assert "never opened" in one_why(check(model, image, "1 write(3,0x1000,64) = 64\n" + EXIT), "write")


# ---------------------------------------------------------------------------------------------------------------------
# The run's own task, and the abort stance
# ---------------------------------------------------------------------------------------------------------------------
DEATH = "--- SIGIOT {si_signo=SIGIOT, si_code=SI_TKILL, si_pid=1, si_uid=1005} ---"
SELF_KILL = TID + "1 tkill(1,SIGIOT) = 0\n" + EXIT
SELF_KILL_TGKILL = TID + "1 tgkill(1,1,SIGIOT) = 0\n" + EXIT
ABORT_RUN = (TID + '1 openat(AT_FDCWD,"in.bin",O_RDONLY) = 3\n'
             "1 rt_sigprocmask(SIG_BLOCK,[SIGHUP SIGINT SIGIOT SIGTERM],0x40007ff8b0,8) = 0 (oldset=[])\n"
             "1 tkill(1,SIGIOT) = 0\n1 rt_sigprocmask(SIG_SETMASK,[],NULL,8) = 0\n" + DEATH)


@needs_model
@pytest.mark.parametrize("text", [SELF_KILL, SELF_KILL_TGKILL, ABORT_RUN], ids=["tkill", "tgkill", "a musl abort"])
def test_a_self_kill_by_stance(model, image, text):
    for stance in ("abort", "either"):
        result = check(model, image, text, stance=stance)
        assert result["verdict"] == "pass" and result["exited"], (stance, result["unmodeled"])
    result = check(model, image, text, stance="off")
    assert result["verdict"] == "fail" and result["exited"]
    assert all(S.STANCE_OFF_REASON in why for why in whys(result)), whys(result)


@needs_model
@pytest.mark.parametrize("line,needle", [
    ("1 tkill(0,SIGIOT) = 0", "pid_positive"),
    ("1 tgkill(5,1,SIGIOT) = 0", "tgkill with a tgid"),
    ("1 tkill(1,SIGTRAP) = 0", "SIGABRT is the one answered"),
    ("1 tkill(1,-1) = 0", "signal above 64"),
    ("1 tkill(1,SIGIOT) = -1 errno=1", "send_sigabrt answers 0"),
    ("1 tkill(2,SIGIOT) = 0", "only the caller's own task"),
])
def test_the_order_of_the_kill_tests(model, image, line, needle):
    # Under stance abort the model reaches these tests; each is checked in Signal.v's order.
    assert needle in one_why(check(model, image, TID + line + "\n" + EXIT, stance="abort"), line.split("(")[0][2:])


@needs_model
@pytest.mark.parametrize("text", [SELF_KILL, SELF_KILL_TGKILL])
def test_a_self_kill_before_the_tid_is_pinned(model, image, text):
    # m_tid is None until set_tid_address, getpid, gettid or setsid has answered.
    result = check(model, image, text.replace(TID, ""), stance="abort")
    assert "pinned the task's id" in one_why(result)


@needs_model
def test_every_tkill_is_unmodeled_under_stance_off(model, image):
    for line in ("1 tkill(0,SIGIOT) = -1 errno=22", "1 tgkill(5,1,SIGIOT) = -1 errno=3",
                 "1 tkill(1,SIGTRAP) = 0", "1 tkill(1,SIGIOT) = 0"):
        why = one_why(check(model, image, TID + line + "\n" + EXIT))
        assert S.STANCE_OFF_REASON in why


@needs_model
@pytest.mark.parametrize("text", [TID + '1 openat(AT_FDCWD,"in.bin",O_RDONLY) = 3\n1 tkill(1,SIGIOT) = 0',
                                  TID + '1 openat(AT_FDCWD,"in.bin",O_RDONLY) = 3\n' + DEATH])
def test_half_an_abort_is_no_end(model, image, text):
    for stance in ("abort", "either"):
        result = check(model, image, text, stance=stance)
        assert result["verdict"] == "fail" and not result["exited"], (stance, result)


@needs_model
def test_stance_spellings(model, image):
    assert S.STANCES == ("off", "abort", "either")
    for word in ("maybe", "ABORT", "on", "", None):
        with pytest.raises(ValueError):
            S.check_trace(model, EXIT, stance=word, binary=image, lengths="exec\n")


def test_the_kill_line_is_qemus_spelling():
    assert S.kill_line(DEATH)
    assert S.kill_line("1 write(1,0x1000,2)" + DEATH)
    assert S.kill_line("--- SIGABRT {si_signo=SIGABRT, si_code=SI_TKILL, si_pid=1, si_uid=0} ---")
    assert not S.kill_line("--- SIGIOT {si_signo=SIGIOT, si_code=SI_USER, si_pid=1, si_uid=0} ---")
    assert not S.kill_line("--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0} ---")
    assert not S.kill_line("7 tkill(7,SIGIOT) = 0")
    # A head whose braces do not hold SI_TKILL does not hide a later one that does.
    assert S.kill_line("--- SIGIOT {si_code=SI_USER} --- --- SIGIOT {si_code=SI_TKILL} ---")
    assert not S.kill_line("--- SIGIOT {si_signo=SIGIOT, si_code=SI_TKILL")


# One long trace line, or a long host-call log, is the guest's to write: each reader must take time linear in it. The
# two slowest cases here took more than two minutes with the quadratic readers; the bound leaves room for a slow
# machine.
LINEAR_SECONDS = 10


def _timed(fn):
    import time
    start = time.monotonic()
    value = fn()
    return value, time.monotonic() - start


def test_a_line_of_many_kill_heads_is_read_in_linear_time():
    line = "--- SIGIOT {" * 200_000
    found, took = _timed(lambda: S.kill_line(line))
    assert not found and took < LINEAR_SECONDS, took


def test_a_line_of_many_records_is_split_in_linear_time():
    line = "1 write(1,0x1000,2)" * 100_000
    records, took = _timed(lambda: list(S.split_records(line)))
    assert len(records) == 100_000 and took < LINEAR_SECONDS, took
    assert records[0][:3] == (1, "write", ["1", "0x1000", "2"]) and records[-1][3] == ""


def test_a_long_run_of_digits_after_a_record_is_read_in_linear_time():
    line = "1 getpid()" + "9" * 300_000
    records, took = _timed(lambda: list(S.split_records(line)))
    assert [r[1] for r in records] == ["getpid"] and took < LINEAR_SECONDS, took


def test_matching_a_long_host_log_takes_linear_time():
    n = 30_000
    log = S.HostLog("exec\n" + "".join(f"read 2 3 {0x100000 + 16 * i:x} 2 0 0 0\n" for i in range(n)))

    def take_all():
        return [log.take("read", {0: S.Arg.full(3), 1: S.Arg.cut(0x100000 + 16 * i), 2: S.Arg.cut(2)}, (1, 2))
                for i in range(n)]
    taken, took = _timed(take_all)
    assert all(t == {1: 0x100000 + 16 * i, 2: 2} for i, t in enumerate(taken)) and took < LINEAR_SECONDS, took
    assert all(row[3] for row in log.lines)


@needs_model
def test_only_the_first_records_task_is_the_run(model, image):
    # The model has one task. Before a fork it answers, a record of another task is unmodeled, changes no state, and
    # is not the run's exit.
    stray = "1 write(1,0x1000,2) = 2\n99 exit_group(0)\n"
    result = check(model, image, stray)
    assert result["verdict"] == "fail" and not result["exited"]
    assert any("not the run's task" in why for why in whys(result))
    # After one, another task's records are the child's, which "is not executed by this model" (Sys/Kernel/Fork.v):
    # they are counted, not checked, and the child's exit is not the run's.
    child = "1 clone(SIGCHLD,0,0,0,0) = 99\n99 getppid() = 1\n99 exit_group(0)\n"
    result = check(model, image, child)
    assert (result["verdict"], result["exited"], result["child_records"]) == ("fail", False, 2), result
    assert result["unmodeled"] == [] and result["names"] == ["clone"]
    result = check(model, image, child + EXIT)
    assert (result["verdict"], result["child_records"]) == ("pass", 2), result
    # A fork qemu logged with no return yet (the child's records landed on its line) is a fork too.
    assert check(model, image, "1 clone(SIGCHLD,0,0,0,0)99 getppid() = 1\n = 99\n" + EXIT)["verdict"] == "pass"
    # A fork the model refuses makes no child the run may have.
    refused = check(model, image, OPEN3 + "1 clone(SIGCHLD,0,0,0,0) = 99\n99 getppid() = 1\n" + EXIT)
    assert any("not the run's task" in why for why in whys(refused)), whys(refused)
    # The child's calls change neither the ledger nor the descriptor table.
    text = ("1 clone(SIGCHLD,0,0,0,0) = 99\n"
            "99 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x100000\n"
            "1 madvise(0x100000,4096,MADV_DONTNEED) = 0\n" + EXIT)
    assert "lies in no tracked mapping" in [u["why"] for u in check(model, image, text)["unmodeled"]
                                            if u["call"] == "madvise"][0]
    # The first record's task is the run, whatever its number.
    assert check(model, image, "77 write(1,0x1000,2) = 2\n77 exit_group(0)")["verdict"] == "pass"


@needs_model
def test_a_count_qemu_cut_decides_only_what_every_register_agrees_on(model, image):
    # With no host line, pread64's count is some 2 + k * 2**32: 3 bytes is more than 2 but not more than the others.
    text = OPEN3 + "1 pread64(3,0x1000,2,0) = 3\n" + EXIT
    assert "the count of pread64" in one_undecided(check(model, image, text, lengths="exec\n"), "pread64")
    # More than MAX_RW_COUNT is more than every candidate's clamp.
    text = OPEN3 + "1 pread64(3,0x1000,2,0) = 2147479553\n" + EXIT
    assert "rw_count_clamp" in one_why(check(model, image, text, lengths="exec\n"), "pread64")
    # Up to the printed count, every candidate agrees.
    assert check(model, image, OPEN3 + "1 pread64(3,0x1000,2,0) = 2\n" + EXIT, lengths="exec\n")["verdict"] == "pass"


# ---------------------------------------------------------------------------------------------------------------------
# What the published model changed, and the rules that read it
# ---------------------------------------------------------------------------------------------------------------------
@needs_model
def test_a_tmp_create_answered_eisdir_is_refused(model, image):
    text = '1 openat(AT_FDCWD,"/tmp/d",O_WRONLY|O_CREAT|O_TRUNC,0600) = -1 errno=21\n' + EXIT
    why = one_why(check(model, image, text), "openat")
    assert "openat_create_spec" in why and "-EISDIR" in why
    ok = ('1 openat(AT_FDCWD,"/tmp/d",O_WRONLY|O_CREAT|O_TRUNC,0600) = 3\n1 close(3) = 0\n'
          '1 openat(AT_FDCWD,"/tmp/d",O_RDONLY) = 3\n' + EXIT)
    assert check(model, image, ok)["verdict"] == "pass"


@needs_model
def test_a_create_of_a_name_answered_eisdir_is_refused(model, image):
    why = one_why(check(model, image, '1 openat(AT_FDCWD,"f",O_WRONLY|O_CREAT|O_TRUNC,0644) = -1 errno=21\n' + EXIT))
    assert "fs_under" in why
    assert check(model, image, '1 openat(AT_FDCWD,".",O_WRONLY|O_CREAT|O_TRUNC,0644) = -1 errno=21\n'
                 + EXIT)["verdict"] == "pass"


@needs_model
def test_a_tmp_unlink_answered_eisdir_is_refused_for_its_reason(model, image):
    why = one_why(check(model, image, '1 unlinkat(AT_FDCWD,"/tmp/d",0) = -1 errno=21\n' + EXIT), "unlinkat")
    assert "-EISDIR" in why and "unlinkat_tmp_spec" in why
    assert check(model, image, '1 unlinkat(AT_FDCWD,"/tmp/d/",0) = -1 errno=2\n' + EXIT)["verdict"] == "pass"


URANDOM = '1 openat(AT_FDCWD,"/dev/urandom",O_RDONLY|O_CLOEXEC) = 4\n'


@needs_model
@pytest.mark.parametrize("call,verdict", [
    ("read(4,0x1000,32) = 32", "pass"),
    ("read(4,0x1000,0) = 0", "pass"),
    ("read(4,0x1000,32) = -1 errno=14", "pass"),
    ("pread64(4,0x1000,32,0) = 32", "pass"),
    ("pread64(4,0x1000,32,-1) = -1 errno=22", "pass"),
    ("read(4,0x1000,32) = 16", "fail"),
    ("read(4,0x1000,32) = 0", "fail"),
    ("read(4,0x1000,32) = -1 errno=11", "fail"),
    ("pread64(4,0x1000,32,0) = 8", "fail"),
    ("readv(4,274886295728,2,0,0,0) = 32", "fail"),
    ("readv(4,274886295728,2,0,0,0) = -1 errno=14", "pass"),
])
def test_urandom_reads_deliver_the_whole_count(model, image, call, verdict):
    result = check(model, image, URANDOM + "1 " + call + "\n" + EXIT)
    assert result["verdict"] == verdict, result["unmodeled"]
    if verdict == "fail":
        assert "urandom" in one_why(result)


@needs_model
def test_a_urandom_read_whose_count_is_cut_declines(model, image):
    text = URANDOM + "1 read(4,0x1000,0) = 0\n" + EXIT
    assert check(model, image, text)["verdict"] == "pass"
    log = faithful_log(text).replace("read 0 4 1000 0", "read 0 4 1000 100000000")
    assert "whole count" in one_why(check(model, image, text, lengths=log), "read")


@needs_model
@pytest.mark.parametrize("brk0,verdict", [
    (0x12000, "pass"),                          # the page-rounded image top, where qemu-user puts it
    (0x12000 + (1 << 30), "pass"),              # brk_aslr_max above it
    (0x12000 + (1 << 30) + 0x1000, "fail"),     # one page past the band
    (0x12000 + (3 << 29), "fail"),              # inside a 2 GiB band, outside the 1 GiB one
    (0x11000, "fail"),                          # below the image top
    (0x12800, "fail"),                          # not page-aligned
])
def test_the_initial_break_band(model, image, brk0, verdict):
    result = check(model, image, f"1 brk(NULL) = {brk0:#x}\n" + EXIT)
    assert result["verdict"] == verdict, result["unmodeled"]
    if verdict == "fail":
        assert "valid_brk" in one_why(result, "brk")


@needs_model
def test_the_band_is_read_from_the_model(tmp_path, image):
    wide = S.Model.load(broken(tmp_path, "State.v", "brk_aslr_max : Z := (1 * 1024", "brk_aslr_max : Z := (2 * 1024"))
    assert wide.brk_aslr_max == 2 << 30
    assert check(wide, image, f"1 brk(NULL) = {0x12000 + (3 << 29):#x}\n" + EXIT)["verdict"] == "pass"


# ---------------------------------------------------------------------------------------------------------------------
# The model as read from the checkout
# ---------------------------------------------------------------------------------------------------------------------
OLD_NAMES = set("""brk close exit exit_group getrandom ioctl lseek mmap mprotect munmap openat read readlinkat
set_tid_address write writev clock_gettime fstat fcntl newfstatat rt_sigprocmask getuid geteuid getcwd pipe2 nanosleep
sched_getaffinity dup3 faccessat rt_sigaction unlinkat readv madvise sched_yield clone3""".split())
NO_ARM = {"getppid", "kill", "set_robust_list", "rt_sigreturn"}


@needs_model
def test_the_table(model):
    assert len(model.numbers) == 90
    assert list(model.numbers) == sorted(model.numbers), "the table keeps its arms sorted by number"
    assert OLD_NAMES <= model.names and not NO_ARM & model.names
    assert {n: model.arms[n] for n in (17, 56, 63, 64, 94, 124, 222, 233, 435, 439)} == {
        17: "getcwd", 56: "openat", 63: "read", 64: "write", 94: "exit_group", 124: "sched_yield", 222: "mmap",
        233: "madvise", 435: "clone3", 439: "faccessat2"}


@needs_model
def test_the_arm_names_are_not_read_from_comments(model):
    # code_sha256 strips comments, so a rule that read a name from one could change without marking the model stale.
    # The numbers come from spec_table's code and SYSCALL_NUMBERS names them; the comments only have to agree.
    text = (pathlib.Path(MODEL_ROOT) / S.MODEL_DIR / "Sys/SyscallTable.v").read_text(encoding="utf-8")
    import re
    commented = {int(n): name for name, n in re.findall(r"\(\*\s*([a-z_0-9]+)\s*\*\)\s*mkSpecArm\s+(\d+)%Z", text)}
    assert commented == model.arms
    stripped = text.replace("(* read            *)", "(* write *)")
    assert S.Model.load(model_copy_with(stripped)).arms == model.arms


def model_copy_with(table_text, _cache={}):
    """A model checkout whose Sys/SyscallTable.v is `table_text`."""
    import tempfile
    root = pathlib.Path(tempfile.mkdtemp(prefix="ov-model."))
    for rel in MODEL_FILES_READ:
        dst = root / S.MODEL_DIR / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        src = (pathlib.Path(MODEL_ROOT) / S.MODEL_DIR / rel).read_text(encoding="utf-8")
        dst.write_text(table_text if rel == "Sys/SyscallTable.v" else src, encoding="utf-8")
    return root


@needs_model
def test_every_arm_has_a_rule_or_passes_on_its_name(model):
    assert set(S.GATES) | S.NAME_ONLY == set(model.names)
    assert not set(S.GATES) & S.NAME_ONLY
    assert set(S.SYSCALL_NUMBERS) >= set(model.names)


@needs_model
def test_an_arm_with_no_rule_is_not_called_modeled(model, image):
    extra = S.Model(model.root, model.arms, model.brk_aslr_max)
    extra.names = frozenset(model.names | {"brand_new"})
    result = check(extra, image, "1 brand_new(1) = 0\n" + EXIT)
    assert "no rule for" in one_why(result, "brand_new")


@needs_model
def test_the_rules_were_read_against_this_checkout():
    assert S.MODEL_FILES, "MODEL_FILES names the files the rules rest on"
    assert model_release.stale(MODEL_ROOT, S.MODEL_FILES) == [], (
        f"{MODEL_ENV} is not the model at {S.MODEL_COMMIT}, or a rule's file changed")
    assert all(path.startswith(S.MODEL_DIR + "/") for path in S.MODEL_FILES)
    for rel in MODEL_FILES_READ + ("Fs.v", "Monad.v", "Run.v", "Sys/Syscall.v", "Sys/Dispatch.v"):
        assert f"{S.MODEL_DIR}/{rel}" in S.MODEL_FILES
    # Every model file the checkout has under the directories the rules read is hashed.
    base = pathlib.Path(MODEL_ROOT) / S.MODEL_DIR
    for path in list(base.glob("Sys/**/*.v")) + [base / n for n in ("Fs.v", "Monad.v", "Run.v", "Specs.v", "State.v")]:
        assert f"{S.MODEL_DIR}/{path.relative_to(base)}" in S.MODEL_FILES, path


@needs_model
def test_the_constants_read_at_run_time(model):
    assert model.brk_aslr_max == 1 << 30


def broken(tmp_path, rel, old, new):
    """A model copy in which `old` in file `rel` is replaced by `new` (it must be there)."""
    def edit(r, text):
        if r != rel:
            return text
        assert old in text, (rel, old)
        return text.replace(old, new)
    return model_copy(tmp_path, edit)


@needs_model
@pytest.mark.parametrize("rel,old,new,needle", [
    ("Sys/SyscallTable.v", "  nil.\n", "  (* read *) mkSpecArm  63%Z (fun i => read_spec i) ::\n  nil.\n",
     "more than once"),
    ("Sys/SyscallTable.v", "  nil.\n", "  (* x *) mkSpecArm (0x40)%Z (fun i => x i) ::\n  nil.\n", "cannot read"),
    ("Sys/SyscallTable.v", "  nil.\n", "  (* x *) mkSpecArm 300%Z (fun i => x i) ::\n  nil.\n",
     "SYSCALL_NUMBERS does not name"),
    ("Sys/SyscallTable.v", "Definition spec_table", "Definition other_table", "no `Definition spec_table"),
    ("Specs.v", "arm_numbers spec_table", "[63; 64]%Z", "modeled_sysnos"),
    ("Sys/Uapi.v", "MAP_FIXED_NOREPLACE : Z := 1048576%Z", "MAP_FIXED_NOREPLACE : Z := 2097152%Z", "0x100000"),
    ("Sys/Uapi.v", "MADV_DONTNEED : Z := 4%Z", "MADV_DONTNEED : Z := 8%Z", "MADV_DONTNEED as 0x8"),
    ("Sys/Mm/Mmap.v", "Definition mmap_noreplace_rw_b", "Definition mmap_noreplace_rw_b_old", "mmap_noreplace_rw_b"),
    ("Sys/Mm/Madvise.v", "if madvise_dontneed_ok h addr n then", "if true then", "madvise_dontneed_ok"),
    ("Sys/SyscallTable.v", "mkSpecArm 233%Z", "mkSpecArm 234%Z", "SYSCALL_NUMBERS does not name"),
    ("State.v", "Definition brk_aslr_max : Z :=", "Definition brk_aslr_max_old : Z :=", "brk_aslr_max"),
])
def test_a_model_these_rules_cannot_read_is_refused(tmp_path, rel, old, new, needle):
    with pytest.raises(Failed, match=needle):
        S.Model.load(broken(tmp_path, rel, old, new))


@needs_model
def test_prose_that_names_an_arm_does_not_count(tmp_path):
    root = broken(tmp_path, "Sys/Mm/Mmap.v", "Definition mmap_noreplace_flags_b",
                  "(* Definition mmap_noreplace_flags_b *) Definition mmap_noreplace_flags_b_gone")
    with pytest.raises(Failed, match="mmap_noreplace_flags_b"):
        S.Model.load(root)


@needs_model
def test_a_copy_of_the_model_loads_the_same(tmp_path, model):
    copy = S.Model.load(model_copy(tmp_path))
    assert (copy.arms, copy.brk_aslr_max) == (model.arms, model.brk_aslr_max)


# ---------------------------------------------------------------------------------------------------------------------
# The image
# ---------------------------------------------------------------------------------------------------------------------
@needs_model
def test_the_image_decides_the_memory_arms(model, image):
    in_image = [
        "1 mmap(0x10000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = 0x10000",
        "1 munmap(0x11000,4096) = 0",
        "1 madvise(0x10000,4096,MADV_DONTNEED) = 0",
        "1 mmap(0x10000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0) = 0x10000",
    ]
    for line in in_image:
        assert "image" in one_why(check(model, image, line + "\n" + EXIT)), line
    eexist = ("1 mmap(0x10000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0) = -1 "
              "errno=17 (File exists)\n" + EXIT)
    assert check(model, image, eexist)["verdict"] == "pass"


@needs_model
def test_without_the_binary_only_ranges_above_the_first_break_are_clear(model):
    def run(text):
        return S.check_trace(model, text, stance="off", lengths=faithful_log(text))
    fixed = "1 mmap({0},4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = {0}\n"
    assert run("1 brk(NULL) = 0x100000\n" + fixed.format("0x200000") + EXIT)["verdict"] == "pass"
    below = "1 brk(NULL) = 0x100000\n" + fixed.format("0x80000") + EXIT
    assert S.IMAGE_UNKNOWN in one_undecided(run(below), "mmap")
    assert S.IMAGE_UNKNOWN in one_undecided(run(fixed.format("0x200000") + EXIT), "mmap")
    unmap = "1 brk(NULL) = 0x100000\n1 munmap(0x80000,4096) = 0\n" + EXIT
    assert S.IMAGE_UNKNOWN in one_undecided(run(unmap), "munmap")


def test_image_spans_round_out_to_pages(tmp_path):
    path = tmp_path / "t.plain"
    path.write_bytes(elf_bytes([(0x10100, 0x80), (0x12F00, 0x200), (0x20000, 0)]))
    assert S.image_spans(path) == [(0x10000, 0x1000), (0x12000, 0x2000)]


@pytest.mark.parametrize("data,needle", [
    (b"not an elf file at all" * 4, "not a 64-bit"),
    (elf_bytes([(0x10000, 0x1000)], machine=62), "not a RISC-V"),
    (elf_bytes([]), "no LOAD"),
    (elf_bytes([(0x10000, 0x1000)])[:100], "program header"),
])
def test_image_spans_refuse_what_they_cannot_read(tmp_path, data, needle):
    path = tmp_path / "bad"
    path.write_bytes(data)
    with pytest.raises(Failed, match=needle):
        S.image_spans(path)


@needs_model
def test_an_unreadable_binary_leaves_the_image_missing_not_an_exception(model):
    # A wrong x86 build is what the binary checks need to report, not a reason to discard every binary's report.
    text = "1 write(1,0x1000,2) = 2\n" + EXIT
    result = S.check_trace(model, text, stance="off", binary="/bin/sh", lengths=faithful_log(text))
    assert result["verdict"] == "pass"
    assert result["image"] == "missing" and "not a RISC-V" in result["image_error"]
    image_dependent = "1 brk(NULL) = 0x100000\n" \
                      "1 mmap(0x80000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = 0x80000\n" \
                      + EXIT
    result = S.check_trace(model, image_dependent, stance="off", binary="/bin/sh",
                           lengths=faithful_log(image_dependent))
    assert result["verdict"] == "undecided"
    assert result["image"] == "missing" and S.IMAGE_UNKNOWN in one_undecided(result, "mmap")


# ---------------------------------------------------------------------------------------------------------------------
# A forged trace
# ---------------------------------------------------------------------------------------------------------------------
@needs_model
def test_a_path_cannot_hide_an_openat_flag_word(model, image):
    # qemu's print_string escapes nothing, so a guest path can hold `",`. The flag word is the text after the LAST
    # `",`, which is the real one.
    forged = '1 openat(AT_FDCWD,"a",O_RDONLY,"b",O_WRONLY|O_CREAT|O_TRUNC,0600) = 3\n' + EXIT
    assert check(model, image, forged)["verdict"] == "pass"
    path, flags, mode = S.openat_path('"a",O_RDONLY,"b",O_WRONLY|O_CREAT,0600')
    assert (path, flags, mode) == ('a",O_RDONLY,"b', "O_WRONLY|O_CREAT", "0600")
    # The word the record ends with is the one judged, so a forged O_RDONLY in the path hides nothing.
    hidden = '1 openat(AT_FDCWD,"a",O_RDONLY,"b",O_WRONLY|O_DIRECT,0600) = 3\n' + EXIT
    assert "modeled_open_flags" in one_why(check(model, image, hidden), "openat")


@needs_model
def test_a_forged_exit_line_in_a_path(model, image):
    # A newline in a guest path puts a whole line of qemu's own shape into the trace. The line it forges is read as a
    # record of its own, so the forged exit is seen; the record it broke has no closing parenthesis and is refused.
    forged = '1 openat(AT_FDCWD,"a\n1 exit_group(0)\n'
    result = check(model, image, forged)
    assert result["verdict"] == "undecided"
    assert "no closing parenthesis" in one_undecided(result, "openat")


@needs_model
def test_an_unknown_syscall_number(model, image):
    result = check(model, image, "1 Unknown syscall 500\n" + EXIT)
    assert "no arm in spec_table" in one_why(result, "syscall 500")
    assert result["calls"] == 2 and "syscall 500" in result["names"]
    # 435 is clone3, an arm: the reason says so, and names the call by its name.
    result = check(model, image, "1 Unknown syscall 435\n" + EXIT)
    why = one_why(result, "clone3")
    assert "arguments" in why and "ENOSYS" in why


# ---------------------------------------------------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------------------------------------------------
@needs_model
def test_the_report_shape(model, image):
    text = ("1 getppid() = 1\n1 getppid() = 1\n1 kill(1,SIGTERM) = 0\n1 getppid() = 1\n"
            "1 write(1,0x1000,2) = 2\n" + EXIT)
    result = check(model, image, text)
    assert set(result) == {"verdict", "calls", "names", "unmodeled", "undecided", "exited", "host_log", "image",
                           "image_error", "child_records"}
    assert (result["image"], result["image_error"]) == ("present", None)
    assert result["calls"] == 6
    assert result["names"] == ["exit_group", "getppid", "kill", "write"]
    assert [u["call"] for u in result["unmodeled"]] == ["getppid", "kill"]
    assert all("\n" not in u["why"] for u in result["unmodeled"])


def test_the_record_splitter():
    assert [r[:2] for r in S.split_records("12 write(1,0x1000,2)13 close(3) = 0")] == [(12, "write"), (13, "close")]
    ((tid, name, args, tail, closed),) = S.split_records('7 openat(AT_FDCWD,"a,b(c",O_RDONLY) = 3 (x)')
    assert (tid, name, args, S.parse_ret(tail), closed) == (7, "openat", ["AT_FDCWD", '"a,b(c"', "O_RDONLY"], 3, True)
    assert list(S.split_records(" = 64")) == []
    assert S.parse_ret(" = -1 errno=2 (No such file)") == -1 and S.parse_ret(" = 0x7fff7000") == 0x7FFF7000
    ((*_, closed),) = S.split_records('1 openat(AT_FDCWD,"a')
    assert not closed


def test_the_32_bit_argument_reader():
    cut, full = S.Arg.cut(-1), S.Arg.full(0x100000000)
    assert (cut.v, cut.exact) == (0xFFFFFFFF, False)
    assert (full.v, full.exact) == (0x100000000, True)
    assert cut.le(0xFFFFFFFF) is None and cut.le(1) is False and full.le(0x100000000) is True
    assert S.Arg.cut(0).is_zero() is None and S.Arg.full(0).is_zero() is True and S.Arg.cut(1).is_zero() is False
    assert S.Arg.cut(0x1000).aligned(4096) is True and S.Arg.cut(1).aligned(4096) is False
    assert S.Arg.cut(4).eq(4) is None and S.Arg.cut(4).eq(5) is False and S.Arg.full(4).eq(4) is True
    assert S.Arg.cut(4).eq(S.TWO_POW_32 + 4) is None and S.Arg.cut(4).eq(3) is False


# ---------------------------------------------------------------------------------------------------------------------
# A real run: giflib's dgif_target, the AddressSanitizer build, on six zero bytes under qemu 8.2.2
# ---------------------------------------------------------------------------------------------------------------------
# Recorded with tools/checks/run-binaries and tools/checks/host-calls.c. The runtime opens with three
# MAP_FIXED_NOREPLACE shadow mappings, two of which qemu prints with a length its 32-bit format cut (the 1 TiB gap as
# 0, the high shadow as a negative number), and reserves a 128 GiB allocator arena that it prints as 69632. qemu holds
# its own -D log on descriptor 3, so the input opens at 4. The log is the run's own, with 500 of its 503 identical
# writes to that log descriptor left out: they belong to no guest call, and the three kept ones stand for them.
# The trace, line by line: qemu prints a record on one line, and three of them are longer than this file's
# lines, so those are written as two pieces of the one string.
GIFLIB_TRACE = "".join(line + "\n" for line in [
    "66 set_tid_address(0x6237c0) = 66",
    "66 mmap(0x000000007fff7000,268435456,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE|"
    "MAP_NORESERVE,-1,0) = 0x000000007fff7000",
    "66 mmap(0x000000008fff7000,0,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE|"
    "MAP_NORESERVE,-1,0) = 0x000000008fff7000",
    "66 mmap(0x000001008fff7000,-268431360,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE|"
    "MAP_NORESERVE,-1,0) = 0x000001008fff7000",
    "66 mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x00002aaaab2ad000",
    "66 mmap(NULL,3727360,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x00002aaaab2bd000",
    "66 mmap(NULL,69632,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE,-1,0) = 0x00002aaaab64b000",
    "66 mmap(0x00002acaab650000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|"
    "MAP_FIXED,-1,0) = 0x00002acaab650000",
    "66 mmap(NULL,8388608,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE,-1,0) = 0x00002acaab65c000",
    "66 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x00002acaabe5c000",
    "66 mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x00002acaabe5d000",
    "66 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x00002acaabe6d000",
    "66 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x00002acaabe6e000",
    "66 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x00002acaabe6f000",
    "66 munmap(0x00002acaabe6f000,4096) = 0",
    "66 mmap(NULL,11571200,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x00002acaabe70000",
    "66 brk(NULL) = 0x0000000000626000",
    "66 brk(0x0000000000628000) = 0x0000000000628000",
    "66 mmap(0x0000000000626000,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = 0x0000000000626000",
    "66 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x00002acaac979000",
    "66 mmap(NULL,1048576,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x00002acaac97a000",
    "66 mmap(NULL,8388608,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE,-1,0) = 0x00002acaaca7a000",
    "66 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x00002acaad27a000",
    "66 openat(AT_FDCWD,\"input.bin\",O_RDONLY|O_LARGEFILE) = 4",
    "66 mmap(NULL,73728,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) = 0x00002acaad27b000",
    "66 mmap(0x00002acaab65c000,131072,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|"
    "MAP_FIXED,-1,0) = 0x00002acaab65c000",
    "66 read(4,0x5f2c50,65536) = 6",
    "66 read(4,0x5f2c50,65530) = 0",
    "66 close(4) = 0",
    "66 mmap(0x00002aabab650000,262144,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|"
    "MAP_FIXED,-1,0) = 0x00002aabab650000",
    "66 mmap(0x00002aac8b650000,262144,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|"
    "MAP_FIXED,-1,0) = 0x00002aac8b650000",
    "66 mmap(0x00002ab0ab650000,262144,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|"
    "MAP_FIXED,-1,0) = 0x00002ab0ab650000",
    "66 mmap(0x00002ab18b650000,262144,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|"
    "MAP_FIXED,-1,0) = 0x00002ab18b650000",
    "66 mmap(0x00002ac6ab650000,262144,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|"
    "MAP_FIXED,-1,0) = 0x00002ac6ab650000",
    "66 mmap(0x00002ac78b650000,262144,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|"
    "MAP_FIXED,-1,0) = 0x00002ac78b650000",
    "66 mmap(0x00002ac2ab650000,262144,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|"
    "MAP_FIXED,-1,0) = 0x00002ac2ab650000",
    "66 mmap(0x00002ac38b650000,262144,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|"
    "MAP_FIXED,-1,0) = 0x00002ac38b650000",
    "66 ioctl(1,TIOCGWINSZ,0x00002aaaab2ab8f0) = -1 errno=25 (Inappropriate ioctl for device)",
    "66 writev(1,0x2aaaab2ab888,0x2) = 2",
    "66 exit_group(0)",
])
GIFLIB_CALLS = '''\
exec
getrandom 8 7ceaefc48920 8 1 1000 0 7ceaefc0a4c0
mprotect 0 7ceaefbb0000 5c000 1 80 5555777c57f0 4
mmap 137348473909248 0 801000 0 20022 ffffffff 0
mprotect 0 7ceaeeff8000 800000 3 801000 ffffffff 0
mmap 137348337631232 0 8000000 0 22 ffffffff 0
munmap 0 7ceae6e00000 1200000 1200000 22 ffffffff 0
munmap 0 7ceaec000000 2e00000 1200000 22 ffffffff 0
mprotect 0 7ceae8000000 21000 3 22 ffffffff 0
read 64 4 7ffc3e672240 40 0 0 16
mmap 137348473380864 0 81000 3 22 ffffffff 0
mmap 137348222287872 0 8000000 0 22 ffffffff 0
madvise 0 7ceae0000000 8000000 e 7ceae0000000 ffffffff 0
mprotect 0 7ceae0000000 7fff000 7 7ceae0000000 7fff000 0
getrandom 0 0 0 0 5555777e6a90 0 7ceaefac3390
read 6 5 5555777e2ad0 400 ffffffffffffffb0 0 ffffffff
read 1024 4 7ffc3e6723d0 400 0 0 0
mmap 65536 10000 615098 0 104022 ffffffff 0
munmap 0 10000 615098 10000 104022 ffffffff 0
mmap 65536 10000 616000 0 104022 ffffffff 0
mmap 65536 10000 29000 1 12 4 0
mmap 233472 39000 8c000 1 12 4 28000
mmap 806912 c5000 5000 3 12 4 b3000
mmap 827392 ca000 3000 3 12 4 b7000
mmap 839680 cd000 559000 3 32 ffffffff 0
pread64 1344 4 5555777fb2d0 540 ba098 0 0
mmap 46912496119808 2aaaaaaab000 801000 0 4022 ffffffff 0
mmap 46912496119808 2aaaaaaab000 801000 3 32 ffffffff 0
mprotect 0 2aaaaaaab000 1000 0 7ceaefc397d0 0 0
mmap 46912504512512 2aaaab2ac000 1000 0 4022 ffffffff 0
mmap 46912504512512 2aaaab2ac000 1000 0 4032 ffffffff 0
mmap 46912504512512 2aaaab2ac000 1000 3 32 ffffffff 0
mprotect 0 2aaaab2ac000 1000 3 7ffc3e672240 0 0
mprotect 0 2aaaab2ac000 1000 1 5555777fb370 0 0
getrandom 16 7ffc3e671c90 10 0 2aaaab2acfff 0 0
write 28 3 555577809c70 1c 1 0 0
write 3 3 555577809c70 3 1 0 ffffffffff9fc848
write 3 3 555577809c70 3 0 0 0
mmap 2147446784 7fff7000 10000000 3 104022 ffffffff 0
mmap 2415882240 8fff7000 10000000000 0 104022 ffffffff 0
mmap 1101927510016 1008fff7000 6fff0001000 3 104022 ffffffff 0
mmap 46912504516608 2aaaab2ad000 10000 0 4022 ffffffff 0
mmap 46912504516608 2aaaab2ad000 10000 3 32 ffffffff 0
mmap 46912504582144 2aaaab2bd000 38e000 0 4022 ffffffff 0
mmap 46912504582144 2aaaab2bd000 38e000 3 32 ffffffff 0
mmap 46912508309504 2aaaab64b000 2000011000 0 4022 ffffffff 0
mmap 46912508309504 2aaaab64b000 2000011000 0 4032 ffffffff 0
mmap 47049947283456 2acaab650000 1000 3 32 ffffffff 0
mmap 47049947332608 2acaab65c000 800000 0 4022 ffffffff 0
mmap 47049947332608 2acaab65c000 800000 0 4032 ffffffff 0
mmap 47049955721216 2acaabe5c000 1000 0 4022 ffffffff 0
mmap 47049955721216 2acaabe5c000 1000 3 32 ffffffff 0
mmap 47049955725312 2acaabe5d000 10000 0 4022 ffffffff 0
mmap 47049955725312 2acaabe5d000 10000 3 32 ffffffff 0
mmap 47049955790848 2acaabe6d000 1000 0 4022 ffffffff 0
mmap 47049955790848 2acaabe6d000 1000 3 32 ffffffff 0
mmap 47049955794944 2acaabe6e000 1000 0 4022 ffffffff 0
mmap 47049955794944 2acaabe6e000 1000 3 32 ffffffff 0
mmap 47049955799040 2acaabe6f000 1000 0 4022 ffffffff 0
mmap 47049955799040 2acaabe6f000 1000 3 32 ffffffff 0
munmap 0 2acaabe6f000 1000 fff 0 0 0
mmap 47049955803136 2acaabe70000 b09000 0 4022 ffffffff 0
mmap 47049955803136 2acaabe70000 b09000 3 32 ffffffff 0
mmap 6447104 626000 2000 3 100022 ffffffff 0
mmap 6447104 626000 1000 0 32 ffffffff 0
mmap 47049967374336 2acaac979000 1000 0 4022 ffffffff 0
mmap 47049967374336 2acaac979000 1000 3 32 ffffffff 0
mmap 47049967378432 2acaac97a000 100000 0 4022 ffffffff 0
mmap 47049967378432 2acaac97a000 100000 3 32 ffffffff 0
mmap 47049968427008 2acaaca7a000 800000 0 4022 ffffffff 0
mmap 47049968427008 2acaaca7a000 800000 3 4032 ffffffff 0
mmap 47049976815616 2acaad27a000 1000 0 4022 ffffffff 0
mmap 47049976815616 2acaad27a000 1000 3 32 ffffffff 0
getcwd 5 7ffc3e66fb80 400 69 0 2aaaab2abfd8 1
mmap 47049976819712 2acaad27b000 12000 0 4022 ffffffff 0
mmap 47049976819712 2acaad27b000 12000 3 32 ffffffff 0
mmap 47049947332608 2acaab65c000 20000 3 32 ffffffff 0
read 6 4 5f2c50 10000 0 0 7ceae00ece40
read 0 4 5f2c50 fffa 0 0 7ceae00ee480
mmap 46916803297280 2aabab650000 40000 3 32 ffffffff 0
mmap 46920561393664 2aac8b650000 40000 3 32 ffffffff 0
mmap 46938278133760 2ab0ab650000 40000 3 32 ffffffff 0
mmap 46942036230144 2ab18b650000 40000 3 32 ffffffff 0
mmap 47032767414272 2ac6ab650000 40000 3 32 ffffffff 0
mmap 47036525510656 2ac78b650000 40000 3 32 ffffffff 0
mmap 47015587545088 2ac2ab650000 40000 3 32 ffffffff 0
mmap 47019345641472 2ac38b650000 40000 3 32 ffffffff 0
'''
GIFLIB_LOADS = [(65536, 167936), (233472, 573440), (806912, 20480), (827392, 5619712)]


@pytest.fixture(scope="session")
def giflib_image(tmp_path_factory):
    """A binary with the LOAD segments of that giflib build."""
    path = tmp_path_factory.mktemp("giflib") / "dgif_target.asan"
    path.write_bytes(elf_bytes(GIFLIB_LOADS))
    return str(path)


def gif(model, image, text=None, lengths=None):
    return S.check_trace(model, GIFLIB_TRACE if text is None else text, stance="off", binary=image,
                         lengths=GIFLIB_CALLS if lengths is None else lengths)


def gif_plus(model, image, lines):
    """The real run with `lines` added before its exit, and the host-call log those calls would leave."""
    added = "".join(f"66 {line}\n" for line in lines)
    text = GIFLIB_TRACE.replace("66 exit_group(0)\n", added + "66 exit_group(0)\n")
    return gif(model, image, text, GIFLIB_CALLS + faithful_log(added, started=False))


@needs_model
def test_a_real_asan_run_passes_with_its_host_call_log(model, giflib_image):
    result = gif(model, giflib_image)
    assert result["verdict"] == "pass", result["unmodeled"]
    assert (result["calls"], result["host_log"], result["exited"]) == (40, "present", True)
    assert "openat" in result["names"] and "writev" in result["names"]


@needs_model
def test_the_real_run_without_its_host_call_log(model, giflib_image):
    # A log that holds the run's start and no call line: every cut argument declines, and nothing passes on a guess.
    bare = gif(model, giflib_image, lengths="exec\n")
    assert bare["verdict"] == "undecided" and bare["unmodeled"] == []
    assert all("not pinned" in u["why"] for u in bare["undecided"]), bare["undecided"]
    # No log at all: the check decides nothing.
    assert gif(model, giflib_image, lengths="")["verdict"] == "undecided"


@needs_model
def test_the_real_run_with_a_host_line_changed(model, giflib_image):
    # The high shadow's length is 0x6FFF0001000; without that line the printed -268431360 stands and declines.
    short = GIFLIB_CALLS.replace("mmap 1101927510016 1008fff7000 6fff0001000 3 104022 ffffffff 0\n", "")
    assert "not pinned" in one_undecided(gif(model, giflib_image, lengths=short), "mmap")
    wrong = GIFLIB_CALLS.replace("6fff0001000 3 104022", "6fff0002000 3 104022")
    assert gif(model, giflib_image, lengths=wrong)["verdict"] != "pass"


@needs_model
def test_the_real_run_knows_which_descriptor_is_qemus(model, giflib_image):
    # qemu holds its -D log on descriptor 3, so the run's input opens at 4 and its two reads of it are answered (the
    # whole-run test above). A guest call on qemu's own descriptor, and one on the input after the run closed it, are
    # both descriptors the model's table does not have, and only -EBADF is its answer.
    assert "never opened" in one_why(gif_plus(model, giflib_image, ["write(3,0x5f2c50,16) = 16"]), "write")
    assert "never opened" in one_why(gif_plus(model, giflib_image, ["read(4,0x5f2c50,16) = 16"]), "read")
    assert gif_plus(model, giflib_image, ["read(4,0x5f2c50,16) = -1 errno=9"])["verdict"] == "pass"


@needs_model
@pytest.mark.parametrize("line,verdict,needle", [
    # the low shadow is read-write, the 1 TiB gap PROT_NONE (vm_noaccess)
    ("madvise(0x000000007fff7000,4096,MADV_DONTNEED) = 0", "pass", None),
    ("madvise(0x000000008fff7000,4096,MADV_DONTNEED) = 0", "fail", "vm_noaccess"),
    # inside the 128 GiB arena: a 256 KiB rw commit, and the PROT_NONE page just past it
    ("madvise(0x00002aabab650000,262144,MADV_DONTNEED) = 0", "pass", None),
    ("madvise(0x00002aabab690000,4096,MADV_DONTNEED) = 0", "fail", "vm_noaccess"),
    # the guard page over the heap's last page
    ("madvise(0x0000000000626000,4096,MADV_DONTNEED) = 0", "fail", "vm_noaccess"),
    ("madvise(0x0000000000627000,4096,MADV_DONTNEED) = 0", "pass", None),
    # the image
    ("madvise(0x0000000000010000,4096,MADV_DONTNEED) = 0", "fail", "image"),
    ("munmap(0x0000000000010000,4096) = 0", "fail", "image"),
])
def test_the_real_runs_ledgers(model, giflib_image, line, verdict, needle):
    result = gif_plus(model, giflib_image, [line])
    assert result["verdict"] == verdict, result["unmodeled"]
    if needle:
        assert needle in one_why(result)


# ---------------------------------------------------------------------------------------------------------------------
# What the trace does not decide
# ---------------------------------------------------------------------------------------------------------------------
@needs_model
@pytest.mark.parametrize("text,call,needle", [
    ("1 brk(0x102000) = 0x102000\n" + EXIT, "brk", "first brk call is not a query"),
    ('1 openat(AT_FDCWD,"a-very-long-name...",O_RDONLY) = 3\n' + EXIT, "openat", "cut short"),
    ('1 unlinkat(AT_FDCWD,"a-very-long-name...",0) = 0\n' + EXIT, "unlinkat", "cut short"),
    ("1 mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS)\n" + EXIT, "mmap", "unparseable"),
    ("1 madvise(0x100000,4096,MADV_HWPOISON) = 0\n" + EXIT, "madvise", "unparseable advice"),
    ('1 openat(AT_FDCWD,"a\n' + EXIT, "openat", "no closing parenthesis"),
])
def test_what_the_trace_does_not_decide(model, image, text, call, needle):
    assert needle in one_undecided(check(model, image, text), call)


@needs_model
@pytest.mark.parametrize("after", [
    "1 madvise(0x100000,4096,MADV_DONTNEED) = 0\n",
    "1 munmap(0x100000,262144) = 0\n",
    "1 mprotect(0x100000,4096,PROT_READ|PROT_WRITE) = 0\n",
    "1 mmap(0x100000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = 0x100000\n",
])
def test_a_failed_map_fixed_over_live_memory_leaves_its_range_undecided(model, image, after):
    # mmap_spec answers -ENOMEM both when it keeps the range and when it destroys it (mmap_fixed_destroyed_next).
    failed = "1 mmap(0x100000,8192,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0) = -1 errno=12\n"
    assert check(model, image, MADVISE_GRANT + failed + EXIT)["verdict"] == "pass"
    assert "does not say which" in one_undecided(check(model, image, MADVISE_GRANT + failed + after + EXIT))


@needs_model
def test_an_undecided_call_is_not_a_verdict_against_the_run(model, image):
    # One undecided call and one unmodeled call: the unmodeled one decides, and both are reported.
    text = "1 brk(0x102000) = 0x102000\n1 getppid() = 1\n" + EXIT
    result = check(model, image, text)
    assert result["verdict"] == "fail"
    assert [u["call"] for u in result["unmodeled"]] == ["getppid"]
    assert [u["call"] for u in result["undecided"]] == ["brk"]


@needs_model
def test_connect_answers_0_for_an_af_unspec_address_on_a_fresh_socket(model, image):
    fresh = SOCKET3 + "1 connect(3,{sa_family=0, sa_data={00, 00, 00, 00, 00, 00}},16) = 0\n" + EXIT
    assert check(model, image, fresh)["verdict"] == "pass"
    # A second one is on a socket the first took out of SkFresh.
    twice = fresh.replace(EXIT, "1 connect(3,{sa_family=0, sa_data={00, 00}},16) = 0\n" + EXIT)
    assert "fresh socket only" in one_why(check(model, image, twice), "connect")
    # An address qemu could not read is printed as a pointer, and then the trace does not show its family.
    pointer = SOCKET3 + "1 connect(3,0x40007ff8b0,16) = 0\n" + EXIT
    assert "as a pointer" in one_undecided(check(model, image, pointer), "connect")


@needs_model
def test_getrandoms_flags_are_sign_extended(model, image):
    assert check(model, image, "1 getrandom(0x7f8eafbfd04c,4,1) = 4\n" + EXIT)["verdict"] == "pass"
    why = one_why(check(model, image, "1 getrandom(0x7f8eafbfd04c,4,2) = 4\n" + EXIT), "getrandom")
    assert "sign extension" in why
