#!/bin/sh -e
# Generated from the build recipe of the oss-fuzz-theorems 2026.10 release; do not edit.
#
# Builds the fuzz targets of cgif into $OUT, each from the pin of the release's target for it.
# compile runs build.sh with bash; the release ran each target's build with sh -e, and so does this.
[ -z "${BASH_VERSION:-}" ] || exec sh -e "$0"
. /usr/local/lib/oss-verify/release-target.sh

# cgif_file_fuzzer: the release's target cgif-cgif_file_fuzzer
(
ov_target_begin cgif-cgif_file_fuzzer
build_lib() {
  oft_build_meson
  oft_build_harness "fuzz/cgif_file_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build cgif_file_fuzzer
)

# cgif_fuzzer: the release's target cgif-cgif_fuzzer
(
ov_target_begin cgif-cgif_fuzzer
build_lib() {
  oft_build_meson
  oft_build_harness "fuzz/cgif_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build cgif_fuzzer
)

# cgif_rgb_fuzzer: the release's target cgif-cgif_rgb_fuzzer
(
ov_target_begin cgif-cgif_rgb_fuzzer
build_lib() {
  oft_build_meson
  oft_build_harness "fuzz/cgif_rgb_fuzzer.c"
  oft_seal_getenv
  oft_seal_mkstemp
  oft_seal_getpid
}
LIB_ARCHIVE="lib/liboft.a"
LIB_CFLAGS=""
ov_target_build cgif_rgb_fuzzer
)
