"""atheris -- the oft tier's stand-in for google/atheris (frozen into every binary).

WHAT THIS IS. OSS-Fuzz's Python harnesses are written against atheris: they call
atheris.Setup(sys.argv, TestOneInput) and atheris.Fuzz(), and consume their input
through atheris.FuzzedDataProvider. oft runs ONE input per process (the oft driver
cli.c reads argv[1]; src/ossfuzz_adapter.h calls LLVMFuzzerTestOneInput), so the
fuzzing engine is replaced by this module:

  * Setup(args, cb, **kw) records cb and returns list(args). Every keyword atheris
    accepts (enable_python_coverage, custom_mutator, ...) is accepted and ignored:
    they steer input GENERATION, and an oft statement quantifies over every input.
  * Fuzz() returns immediately. (atheris's never returns; the C host,
    atheris_host.c, calls the recorded callback once per LLVMFuzzerTestOneInput.)
  * instrument_imports / instrument_func / instrument_all / enabled_hooks /
    Mutate are coverage and mutation machinery: no-ops (Mutate returns its input).
  * FuzzedDataProvider is a TRANSLITERATION of atheris 3.1.0
    src/native/fuzzed_data_provider.cc (google/atheris e36da74c, 2026-06-17) --
    same byte consumption, same values, same edge behaviour (size_t wrap of
    count*2 / count*4, the ConsumeSmallIntInRange tail-consumption, TypeError for
    a negative size). tier/fdp_difftest.py checks it against the real atheris.

The TestOneInput return value is ignored, as atheris ignores it (its callback type
is std::function<void(py::bytes)>).
"""
import os
import sys

__all__ = [
    "ALL_REMAINING", "Fuzz", "FuzzedDataProvider", "Mutate", "Setup",
    "enabled_hooks", "instrument_all", "instrument_func", "instrument_imports",
    "path",
]

_U64 = (1 << 64) - 1
ALL_REMAINING = _U64
_DBL_MAX = 1.7976931348623157e308
_DBL_MIN = 2.2250738585072014e-308
_DBL_DENORM_MIN = 5e-324

# The recorded TestOneInput; read by atheris_host.c.
_oft_test_one_input = None
_oft_setup_calls = 0


def Setup(args, test_one_input, **kwargs):
    global _oft_test_one_input, _oft_setup_calls
    if not callable(test_one_input):
        raise TypeError("Setup: test_one_input must be callable")
    _oft_test_one_input = test_one_input
    _oft_setup_calls += 1
    return list(args)


def Fuzz():
    if _oft_test_one_input is None:
        raise RuntimeError("You must call Setup() before Fuzz().")
    return None


def Mutate(data, max_size):
    return bytes(data)[:max_size]


class _HookManager:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def instrument_imports(include=None, exclude=None, enable_loader_override=True):
    return _HookManager()


def instrument_func(func):
    return func


def instrument_all():
    return None


class _EnabledHooks:
    def __init__(self):
        self._hooks = set()

    def add(self, hook):
        self._hooks.add(hook)

    def __contains__(self, hook):
        return hook in self._hooks


enabled_hooks = _EnabledHooks()


def path():
    return ""


class _oft_stream:
    """sys.stdout / sys.stderr for the core-only interpreter variant
    (atheris_host.c OFT_PY_CORE_ONLY): unbuffered, one write(2) per call, and no
    fstat/fcntl probing of the fd the way io.open(fd) does it."""

    encoding = "utf-8"
    errors = "surrogateescape"

    def __init__(self, fd):
        self._fd = fd

    def write(self, s):
        b = s.encode(self.encoding, self.errors)
        off = 0
        while off < len(b):
            off += os.write(self._fd, b[off:])
        return len(s)

    def flush(self):
        return None

    def isatty(self):
        return False

    def fileno(self):
        return self._fd

    def writable(self):
        return True

    def readable(self):
        return False



class _oft_null_stream(_oft_stream):
    """sys.stdout / sys.stderr of the QUIET build (atheris_host.c asks the plugin,
    python_tier_plugin.h oft_py_quiet()): the loud build with the writes removed,
    which is what -DHARNESS_QUIET means for a C target. Python-level output --
    print(), the warnings module, a library's own sys.stderr.write -- is accepted
    and discarded, so no write(2) is issued. MEASURED need (2026-09-27): parse,
    pyparsing and typing_extensions print a FutureWarning / DeprecationWarning /
    SyntaxWarning on some corpus inputs, which failed check_quiet."""

    def write(self, s):
        return len(s)


def _size_t(v, what):
    # pybind11's size_t caster: an int (bool included) in [0, 2**64); anything
    # else fails overload resolution with a TypeError.
    if not isinstance(v, int):
        try:
            v = v.__index__()
        except AttributeError:
            raise TypeError("%s: incompatible function arguments" % what) from None
    if v < 0 or v > _U64:
        raise TypeError("%s: incompatible function arguments" % what)
    return int(v)


def _double(v, what):
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return float(v.__float__())
    except AttributeError:
        raise TypeError("%s: incompatible function arguments" % what) from None


class FuzzedDataProvider:
    __slots__ = ("_data", "_pos", "_rem")

    def __init__(self, data):
        if not isinstance(data, bytes):
            raise TypeError("FuzzedDataProvider(): incompatible constructor arguments")
        self._data = data
        self._pos = 0
        self._rem = len(data)

    # -- internals, named after the C++ ------------------------------------
    def _advance(self, n):
        if n > self._rem:
            self._rem = 0
        else:
            self._pos += n
            self._rem -= n

    def _peek(self, n):
        return self._data[self._pos:self._pos + n]

    def _small_int_in_range(self, n, rng):
        # Consumes from the END of the remaining window, one byte per 8 bits.
        result = 0
        offset = 0
        while offset < n and (rng >> offset) > 0 and self._rem != 0:
            self._rem -= 1
            result = ((result << 8) | self._data[self._pos + self._rem]) & _U64
            offset += 8
        if rng != _U64:
            result = result % (rng + 1)
        return result

    def _unicode(self, count, filter_surrogates):
        if count == 0 or self._rem == 0:
            return ""
        if self._rem == 1:
            self._advance(1)
            return ""
        spec = self._data[self._pos]
        self._advance(1)
        if spec & 1:
            n = min(count, self._rem)
            s = bytes(b & 0x7F for b in self._peek(n)).decode("ascii")
            self._advance(n)
            return s
        if spec & 2:
            n = min((count * 2) & _U64, self._rem)
            even = n & ~1
            raw = self._peek(even)
            cps = [raw[i] | (raw[i + 1] << 8) for i in range(0, even, 2)]
            if filter_surrogates:
                cps = [c - 0xD800 if 0xD800 <= c < 0xE000 else c for c in cps]
            self._advance(n)
            return "".join(map(chr, cps))
        n = min((count * 4) & _U64, self._rem)
        group = n & ~3
        raw = self._peek(group)
        cps = []
        for i in range(0, group, 4):
            c = (raw[i] | (raw[i + 1] << 8) | (raw[i + 2] << 16) | (raw[i + 3] << 24)) & 0x1FFFFF
            if c & 0x100000:
                c &= ~0x0F0000
            if filter_surrogates and 0xD800 <= c < 0xE000:
                c -= 0xD800
            cps.append(c)
        self._advance(n)
        return "".join(map(chr, cps))

    def _probability(self):
        n = min(8, self._rem)
        integral = int.from_bytes(self._peek(n), "little")
        self._advance(n)
        return float(integral) / 18446744073709551615.0

    def _float_in_range(self, lo, hi):
        if lo > hi:
            raise RuntimeError("ConsumeFloatInRange: min must be <= max")
        rng = 0.0
        result = lo
        if lo < 0 and hi > 0 and lo + _DBL_MAX < hi:
            rng = (hi / 2) - (lo / 2)
            if self.ConsumeBool():
                result += rng
        else:
            rng = hi - lo
        return result + rng * self._probability()

    # -- public API (atheris.cc's pybind11 table) ----------------------------
    def ConsumeUnicode(self, count):
        return self._unicode(_size_t(count, "ConsumeUnicode"), False)

    def ConsumeUnicodeNoSurrogates(self, count):
        return self._unicode(_size_t(count, "ConsumeUnicodeNoSurrogates"), True)

    def ConsumeString(self, count):
        return self._unicode(_size_t(count, "ConsumeString"), False)

    def ConsumeBytes(self, count):
        n = min(_size_t(count, "ConsumeBytes"), self._rem)
        if not n:
            return b""
        b = self._peek(n)
        self._advance(n)
        return b

    def ConsumeInt(self, nbytes):
        n = min(_size_t(nbytes, "ConsumeInt"), self._rem)
        if n == 0:
            return 0
        v = int.from_bytes(self._peek(n), "little", signed=True)
        self._advance(n)
        return v

    def ConsumeUInt(self, nbytes):
        n = min(_size_t(nbytes, "ConsumeUInt"), self._rem)
        if n == 0:
            return 0
        v = int.from_bytes(self._peek(n), "little", signed=False)
        self._advance(n)
        return v

    def ConsumeIntInRange(self, lo, hi):
        if not isinstance(lo, int) or not isinstance(hi, int):
            raise TypeError("ConsumeIntInRange: incompatible function arguments")
        delta = hi - lo
        if delta < 0:
            raise RuntimeError("ConsumeIntInRange: min must be <= max")
        size = delta.bit_length()
        if size <= 64:
            return lo + self._small_int_in_range(size, delta)
        return lo + (self.ConsumeInt(size // 8) % (delta + 1))

    def ConsumeIntList(self, count, nbytes):
        count = _size_t(count, "ConsumeIntList")
        return [self.ConsumeInt(nbytes) for _ in range(count)]

    def ConsumeIntListInRange(self, count, lo, hi):
        count = _size_t(count, "ConsumeIntListInRange")
        return [self.ConsumeIntInRange(lo, hi) for _ in range(count)]

    def ConsumeFloat(self):
        if not self._rem:
            return 0.0
        t = self._data[self._pos]
        self._advance(1)
        if t <= 10:
            self._advance(min(9, self._rem))
            return (0.0, -0.0, float("inf"), float("-inf"), float("nan"),
                    _DBL_DENORM_MIN, -_DBL_DENORM_MIN, _DBL_MIN, -_DBL_MIN,
                    _DBL_MAX, -_DBL_MAX)[t]
        return self.ConsumeRegularFloat()

    def ConsumeRegularFloat(self):
        return self._float_in_range(-_DBL_MAX, _DBL_MAX)

    def ConsumeProbability(self):
        return self._probability()

    def ConsumeFloatInRange(self, lo, hi):
        return self._float_in_range(_double(lo, "ConsumeFloatInRange"),
                                    _double(hi, "ConsumeFloatInRange"))

    def ConsumeFloatList(self, count):
        return [self.ConsumeFloat() for _ in range(_size_t(count, "ConsumeFloatList"))]

    def ConsumeRegularFloatList(self, count):
        return [self.ConsumeRegularFloat()
                for _ in range(_size_t(count, "ConsumeRegularFloatList"))]

    def ConsumeProbabilityList(self, count):
        return [self._probability()
                for _ in range(_size_t(count, "ConsumeProbabilityList"))]

    def ConsumeFloatListInRange(self, count, lo, hi):
        lo = _double(lo, "ConsumeFloatListInRange")
        hi = _double(hi, "ConsumeFloatListInRange")
        return [self._float_in_range(lo, hi)
                for _ in range(_size_t(count, "ConsumeFloatListInRange"))]

    def PickValueInList(self, lst):
        if not isinstance(lst, list):
            raise TypeError("PickValueInList: incompatible function arguments")
        size = len(lst)
        rng = (size - 1) & _U64
        if size <= 0xFF:
            i = self._small_int_in_range(8, rng)
        elif size <= 0xFFFF:
            i = self._small_int_in_range(16, rng)
        elif size <= 0xFFFFFFFF:
            i = self._small_int_in_range(32, rng)
        else:
            i = self._small_int_in_range(64, rng)
        if i >= size:
            raise IndexError("list index out of range")
        return lst[i]

    def ConsumeBool(self):
        if not self._rem:
            return False
        r = bool(self._data[self._pos] & 1)
        self._advance(1)
        return r

    def remaining_bytes(self):
        return self._rem

    def buffer(self):
        return self._peek(self._rem)

# Copyright 2026 Theorem Labs, PBC
# SPDX-License-Identifier: Apache-2.0
#
# The stand-in for atheris that a Python fuzz target is frozen with. From the build recipe of the
# oss-fuzz-theorems 2026.10 release, in its release spelling. It is compiled into each binary, so every
# line above is as the release has it; this note is at the end, where it moves no line.
