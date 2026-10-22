#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of yajl-ruby into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# json_fuzzer: the release's target yajl-ruby-json_fuzzer
(
ov_target_begin yajl-ruby-json_fuzzer
build_lib() {
  oft_build_blind
  oft_build_harness "json_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""





































build_lib() {
  OFT_BLIND_SKIP=1 oft_build_blind
  oft_build_harness "json_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build json_fuzzer
)
