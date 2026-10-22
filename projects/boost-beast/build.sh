#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of boost-beast into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# http_request: the release's target boost-beast
(
ov_target_begin boost-beast
build_lib() {
  oft_require_target_cxx
  oft_build_cmake
  oft_build_harness "libs/beast/test/fuzz/http_request.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""







build_lib() {
  oft_require_target_cxx
  oft_build_header_only

  OFT_HARNESS_CFLAGS="$(for d in "$BUILDDIR"/src/libs/*/include "$BUILDDIR"/src/libs/*/*/include; do [ -d "$d" ] && printf "%s" "-isystem $d "; done) -H"
  echo "oft: boost-beast: OFT_HARNESS_CFLAGS carries $(set -- $OFT_HARNESS_CFLAGS; echo $#) words"
  oft_build_harness "libs/beast/test/fuzz/http_request.cpp"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
ov_target_build http_request
)
