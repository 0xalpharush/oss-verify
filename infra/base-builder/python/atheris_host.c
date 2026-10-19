/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0
 *
 * The harness object of a Python fuzz target: a static, frozen CPython that runs one OSS-Fuzz atheris harness.
 *
 *   cli.c (the input file) -> ossfuzz_adapter.h
 *     -> LLVMFuzzerInitialize()   here: start the interpreter once and run the
 *                                 frozen harness as __main__ (its main() calls
 *                                 atheris.Setup(sys.argv, TestOneInput) and
 *                                 atheris.Fuzz(); the frozen atheris stand-in
 *                                 keeps the callback and returns)
 *     -> LLVMFuzzerTestOneInput() here: TestOneInput(bytes(payload))
 *
 * It includes the interpreter's headers and their inline functions, so it is compiled with the build's $CC and
 * $CFLAGS, as a library's code is, and goes into the target's archive as harness.o.
 *
 * Exit statuses (the adapter gives 0, 2, 77 and 78; this file adds two):
 *   0   each call returned (its return value is ignored, as atheris ignores it)
 *   2   an uncaught MemoryError, or a failed allocation of the bytes: no memory,
 *       which is what 2 means for the adapter too
 *   77  an uncaught SystemExit in TestOneInput: the fuzz target exited
 *   79  any other uncaught exception: what atheris reports as
 *       "=== Uncaught Python exception: ===", the failure the harness found.
 *       Not 134: nothing here raises SIGABRT.
 *   80  the interpreter or the frozen harness failed before the first input:
 *       a defect of the build, never a finding in the library. A binary that
 *       exits 80 on the empty input is not published.
 * Both are _exit()ed after fflush(stdout): the adapter would turn an exit() in
 * the callback into 77.
 *
 * Nothing here prints. The loud build describes a failure through
 * oft_py_report(), which the adapter defines (driver/python_tier_plugin.h, compiled loud and
 * with -DHARNESS_QUIET), because this object is in both binaries.
 *
 * The interpreter's configuration (each field is public PyConfig or PyPreConfig
 * unless marked PRIVATE), with these switches:
 *   OFT_PY_MALLOC     PyPreConfig.allocator = PYMEM_ALLOCATOR_MALLOC: no pymalloc
 *                     arenas; each object is its own malloc (ASan sees each)
 *   OFT_PY_CORE_ONLY  PRIVATE PyConfig._init_main = 0: the core phase only: no
 *                     path configuration, no sys.std* file objects, no zipimport,
 *                     no builtins.open. This file then gives what harnesses
 *                     need (sys.argv and others, sys.stdout and sys.stderr as fd writers,
 *                     builtins.open = io.open).
 * From the build recipe of the oss-fuzz-theorems 2026.10 release; the code is unchanged, on the same lines. */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <marshal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#define OFT_REL_STR(earlier, release) release /* two spellings; the release's is compiled in */
#include "oft_frozen.h" /* written by pyfreeze.py: the arrays, oft_frozen_modules[], OFT_MAIN_* */

#define OFT_PY_OOM 2
#define OFT_PY_EXITED 77
#define OFT_PY_UNCAUGHT 79
#define OFT_PY_INIT_FAILED 80

/* Defined by the adapter (python_tier_plugin.h): the loud build describes, the quiet
 * build says nothing. Weak, so that an adapter without it still links. */
__attribute__((weak)) void oft_py_report(const char *what, const char *type,
                                         const char *file, int line);
/* 1 in the quiet build, 0 in the loud one (python_tier_plugin.h). Weak: an adapter
 * without it is taken as loud. */
__attribute__((weak)) int oft_py_quiet(void);

static PyObject *oft_cb; /* the harness's TestOneInput */

static void oft_describe(const char *what, PyObject *et, PyObject *ev, PyObject *tb) {
  if (!oft_py_report) return;
  const char *tname = et ? ((PyTypeObject *)et)->tp_name : "?";
  const char *file = "?";
  int line = 0;
  PyObject *last = NULL;
  /* The innermost frame: walk tb_next to the end, read tb_lineno and the code's
   * co_filename. No source lookup, so no file is opened. */
  for (PyObject *t = tb; t && t != Py_None;) {
    last = t;
    PyObject *n = PyObject_GetAttrString(t, "tb_next");
    if (!n) { PyErr_Clear(); break; }
    Py_DECREF(n); /* the traceback chain keeps it alive */
    t = n;
  }
  PyObject *ln = NULL, *fr = NULL, *co = NULL, *fn = NULL;
  if (last) {
    ln = PyObject_GetAttrString(last, "tb_lineno");
    fr = PyObject_GetAttrString(last, "tb_frame");
    if (fr) co = PyObject_GetAttrString(fr, "f_code");
    if (co) fn = PyObject_GetAttrString(co, "co_filename");
    if (ln) line = (int)PyLong_AsLong(ln);
    if (fn && PyUnicode_Check(fn)) file = PyUnicode_AsUTF8(fn);
    PyErr_Clear();
  }
  oft_py_report(what, tname, file ? file : "?", line);
  Py_XDECREF(fn); Py_XDECREF(co); Py_XDECREF(fr); Py_XDECREF(ln);
  (void)ev;
}

/* Map the pending exception to a status and leave. */
static void oft_fail(const char *what, int init) {
  PyObject *et = NULL, *ev = NULL, *tb = NULL;
  PyErr_Fetch(&et, &ev, &tb);
  PyErr_NormalizeException(&et, &ev, &tb);
  int st = init ? OFT_PY_INIT_FAILED : OFT_PY_UNCAUGHT;
  if (et && PyErr_GivenExceptionMatches(et, PyExc_MemoryError)) st = OFT_PY_OOM;
  else if (!init && et && PyErr_GivenExceptionMatches(et, PyExc_SystemExit)) st = OFT_PY_EXITED;
  oft_describe(what, et, ev, tb);
  fflush(stdout);
  _exit(st);
}

static void oft_init_fail(const char *what, PyStatus s) {
  if (oft_py_report) oft_py_report(what, s.err_msg ? s.err_msg : "PyStatus", s.func ? s.func : "?", s.exitcode);
  fflush(stdout);
  _exit(OFT_PY_INIT_FAILED);
}

#define OFT_CHECK(st, what) do { PyStatus _s = (st); if (PyStatus_Exception(_s)) oft_init_fail(what, _s); } while (0)

#ifdef OFT_PY_CORE_ONLY
/* PRIVATE: the four init_interp_main() steps that allocate interpreter state and
 * make no system call (pycore_pylifecycle.h, 3.11). Without _PySignal_Init the first
 * `import signal` dereferences the NULL default and ignore handler objects:
 * packaging's fuzz target crashed at `import signal` (subprocess imports it). */
extern PyStatus _PyFaulthandler_Init(int enable);
extern PyStatus _PyUnicode_InitEncodings(PyThreadState *tstate);
extern int _PySignal_Init(int install_signal_handlers);
extern int _PyTraceMalloc_Init(int enable);
static void oft_core_state(void) {
  OFT_CHECK(_PyFaulthandler_Init(0), "_PyFaulthandler_Init");
  OFT_CHECK(_PyUnicode_InitEncodings(PyThreadState_Get()), "_PyUnicode_InitEncodings");
  if (_PySignal_Init(0) < 0) oft_fail("_PySignal_Init", 1);
  if (_PyTraceMalloc_Init(0) < 0) oft_fail("_PyTraceMalloc_Init", 1);
}

/* What _PySys_UpdateConfig, init_set_builtins_open and init_sys_streams would
 * have provided, reduced to constants. sys.stdout/sys.stderr are the shim's
 * fd writers (os.write, i.e. one write(2) per call, no fstat/fcntl probing). */
/* sys.executable. "" (what CPython gives when it cannot tell) sends
 * sysconfig's module-level _safe_realpath(sys.executable) through getcwd() and an
 * lstat of each component of the working directory (getcwd(1024),
 * newfstatat("/tmp"), ...); an absolute path whose first
 * component does not exist costs one newfstatat("/oft") = -ENOENT. */
#ifndef OFT_PY_EXECUTABLE
#define OFT_PY_EXECUTABLE ""
#endif
static int oft_set_sys_str(const char *k, const char *v) {
  PyObject *o = PyUnicode_FromString(v);
  if (!o) return -1;
  int r = PySys_SetObject(k, o);
  Py_DECREF(o);
  return r;
}
static void oft_core_fixups(PyObject *ath) {
  PyObject *argv = Py_BuildValue("[s]", "fuzz");
  PyObject *empty = PyList_New(0), *empty2 = PyList_New(0), *xo = PyDict_New();
  if (!argv || !empty || !empty2 || !xo) oft_fail("core-fixups", 1);
  if (PySys_SetObject("argv", argv) || PySys_SetObject("orig_argv", argv) ||
      PySys_SetObject("path", empty) || PySys_SetObject("warnoptions", empty2) ||
      PySys_SetObject("_xoptions", xo) || PySys_SetObject("pycache_prefix", Py_None) ||
      PySys_SetObject("_stdlib_dir", Py_None) ||
      PySys_SetObject("dont_write_bytecode", Py_True) ||
      oft_set_sys_str("executable", OFT_PY_EXECUTABLE) || oft_set_sys_str("_base_executable", OFT_PY_EXECUTABLE) ||
      oft_set_sys_str("prefix", OFT_REL_STR("/oft/py", "/oft/py")) || oft_set_sys_str("base_prefix", OFT_REL_STR("/oft/py", "/oft/py")) ||
      oft_set_sys_str("exec_prefix", OFT_REL_STR("/oft/py", "/oft/py")) || oft_set_sys_str("base_exec_prefix", OFT_REL_STR("/oft/py", "/oft/py")) ||
      oft_set_sys_str("platlibdir", "lib"))
    oft_fail("core-fixups", 1);
  Py_DECREF(argv); Py_DECREF(empty); Py_DECREF(empty2); Py_DECREF(xo);
  /* Quiet build: sinks (the shim's _oft_null_stream), so Python-level output --
   * print, warnings -- issues no write(2), as HARNESS_QUIET means for C. */
  PyObject *mk = PyObject_GetAttrString(ath, (oft_py_quiet && oft_py_quiet()) ? OFT_REL_STR("_oft_null_stream", "_oft_null_stream") : OFT_REL_STR("_oft_stream", "_oft_stream"));
  if (!mk) oft_fail(OFT_REL_STR("core-fixups: atheris._oft_stream", "core-fixups: atheris._oft_stream"), 1);
  PyObject *out = PyObject_CallFunction(mk, "i", 1), *err = PyObject_CallFunction(mk, "i", 2);
  if (!out || !err) oft_fail("core-fixups: streams", 1);
  if (PySys_SetObject("stdout", out) || PySys_SetObject("__stdout__", out) ||
      PySys_SetObject("stderr", err) || PySys_SetObject("__stderr__", err) ||
      PySys_SetObject("stdin", Py_None) || PySys_SetObject("__stdin__", Py_None))
    oft_fail("core-fixups: streams", 1);
  Py_DECREF(out); Py_DECREF(err); Py_DECREF(mk);
#if defined(OFT_PY_NO_EPOLL) || defined(OFT_PY_NO_POLL)
  /* The runtime equivalent of building the select module without epoll (and
   * poll): selectors' module-level _can_use() probe creates and closes an epoll
   * instance (epoll_create1(EPOLL_CLOEXEC), which the process model does not have) or polls
   * zero fds, when anything imports subprocess. Removing the attributes before any
   * import makes DefaultSelector fall back exactly as on a platform without them. */
  {
    PyObject *sel = PyImport_ImportModule("select");
    if (!sel) oft_fail("core-fixups: select", 1);
    static const char *gone[] = {
#ifdef OFT_PY_NO_EPOLL
      "epoll", "EPOLLIN",
#endif
#ifdef OFT_PY_NO_POLL
      "poll", "devpoll",
#endif
      NULL};
    for (int i = 0; gone[i]; i++)
      if (PyObject_HasAttrString(sel, gone[i]) && PyObject_DelAttrString(sel, gone[i])) oft_fail("core-fixups: select attr", 1);
    Py_DECREF(sel);
  }
#endif
  PyObject *io = PyImport_ImportModule("io");
  PyObject *bi = PyImport_ImportModule("builtins");
  if (!io || !bi) oft_fail("core-fixups: io/builtins", 1);
  PyObject *op = PyObject_GetAttrString(io, "open");
  if (!op || PyObject_SetAttrString(bi, "open", op)) oft_fail("core-fixups: builtins.open", 1);
  Py_DECREF(op); Py_DECREF(io); Py_DECREF(bi);
}
#endif

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc; (void)argv;
#ifdef OFT_PY_STOCK
  /* The stock configuration, which we build only to measure, never to publish:
   * the DEFAULT (non-isolated) Python configuration, implicit pre-initialisation,
   * nothing turned off. Only the frozen table is added, without which the
   * interpreter cannot find its standard library at all. */
  {
    PyImport_FrozenModules = oft_frozen_modules;
    PyConfig c0;
    PyConfig_InitPythonConfig(&c0);
    c0.parse_argv = 0;
    OFT_CHECK(PyConfig_SetString(&c0, &c0.program_name, L"fuzz"), "program_name");
    wchar_t *av0[1] = {L"fuzz"};
    OFT_CHECK(PyConfig_SetArgv(&c0, 1, av0), "argv");
    OFT_CHECK(Py_InitializeFromConfig(&c0), "Py_InitializeFromConfig");
    PyConfig_Clear(&c0);
  }
#else
  PyPreConfig pre;
  PyPreConfig_InitIsolatedConfig(&pre);
  pre.utf8_mode = 1;          /* fs + stdio encoding utf-8 whatever the C locale says */
  pre.configure_locale = 0;   /* no setlocale(LC_CTYPE, "") */
#ifdef OFT_PY_MALLOC
  pre.allocator = PYMEM_ALLOCATOR_MALLOC;
#endif
  OFT_CHECK(Py_PreInitialize(&pre), "Py_PreInitialize");

  /* The frozen table (encodings, the stdlib closure, the project, the shim) is
   * consulted by Python/import.c ahead of the stdlib's own frozen modules. */
  PyImport_FrozenModules = oft_frozen_modules;

  PyConfig c;
  PyConfig_InitIsolatedConfig(&c);
  c.site_import = 0;
  c.pathconfig_warnings = 0;
  c.install_signal_handlers = 0;  /* no rt_sigaction for SIGINT/SIGPIPE/SIGXFSZ */
  c.use_hash_seed = 1;            /* PYTHONHASHSEED=0: no getrandom, and a run is */
  c.hash_seed = 0;                /* a function of its input (set/dict hash order) */
  c.write_bytecode = 0;
  c.user_site_directory = 0;
  c.faulthandler = 0;
  c.tracemalloc = 0;
  c.buffered_stdio = 1;
  c.parse_argv = 0;
  c.use_frozen_modules = 1;
  c.module_search_paths_set = 1;  /* empty sys.path: the frozen table is the world */
  OFT_CHECK(PyConfig_SetString(&c, &c.program_name, L"fuzz"), "program_name");
  OFT_CHECK(PyConfig_SetString(&c, &c.executable, L"fuzz"), "executable");
  OFT_CHECK(PyConfig_SetString(&c, &c.home, OFT_REL_STR(L"/oft/py", L"/oft/py")), "home"); /* skips ._pth, pyvenv.cfg, build-dir probes */
  wchar_t *av[1] = {L"fuzz"};
  OFT_CHECK(PyConfig_SetArgv(&c, 1, av), "argv");
#ifdef OFT_PY_CORE_ONLY
  c._init_main = 0;
#endif
  OFT_CHECK(Py_InitializeFromConfig(&c), "Py_InitializeFromConfig");
  PyConfig_Clear(&c);
#ifdef OFT_PY_CORE_ONLY
  oft_core_state();
#endif
#endif /* OFT_PY_STOCK */

  PyObject *ath = PyImport_ImportModule("atheris");
  if (!ath) oft_fail("import atheris (the frozen shim)", 1);
#ifdef OFT_PY_CORE_ONLY
  oft_core_fixups(ath);
#endif

  /* The harness, as __main__, so `if __name__ == "__main__": main()` runs. */
  PyObject *m = PyImport_AddModule("__main__"); /* borrowed */
  if (!m) oft_fail("__main__", 1);
  PyObject *d = PyModule_GetDict(m);
  if (!PyDict_GetItemString(d, "__builtins__") &&
      PyDict_SetItemString(d, "__builtins__", PyEval_GetBuiltins()))
    oft_fail("__main__.__builtins__", 1);
  PyObject *code = PyMarshal_ReadObjectFromString((const char *)OFT_MAIN_CODE, (Py_ssize_t)OFT_MAIN_SIZE);
  if (!code) oft_fail("unmarshal the harness", 1);
  PyObject *r = PyEval_EvalCode(code, d, d);
  Py_DECREF(code);
  if (!r) oft_fail("run the harness module", 1);
  Py_DECREF(r);

  oft_cb = PyObject_GetAttrString(ath, OFT_REL_STR("_oft_test_one_input", "_oft_test_one_input"));
  Py_DECREF(ath);
  if (!oft_cb || oft_cb == Py_None) {
    if (!PyErr_Occurred()) PyErr_SetString(PyExc_RuntimeError, "the harness never called atheris.Setup()");
    oft_fail("atheris.Setup", 1);
  }
  return 0;
}

static void oft_flush_stdio(void) {
  /* Python-level buffers only; nothing is written when nothing was printed. */
  static const char *names[2] = {"stdout", "stderr"};
  for (int i = 0; i < 2; i++) {
    PyObject *f = PySys_GetObject(names[i]); /* borrowed */
    if (!f || f == Py_None) continue;
    PyObject *r = PyObject_CallMethod(f, "flush", NULL);
    if (!r) PyErr_Clear(); else Py_DECREF(r);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  PyObject *b = PyBytes_FromStringAndSize((const char *)data, (Py_ssize_t)size);
  if (!b) oft_fail("bytes(payload)", 0);
  PyObject *r = PyObject_CallOneArg(oft_cb, b);
  Py_DECREF(b);
  if (!r) oft_fail("TestOneInput", 0);
  Py_DECREF(r);
  oft_flush_stdio();
  return 0;
}
