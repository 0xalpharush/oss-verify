/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0 */
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include "example.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string input(reinterpret_cast<const char *>(data), size);
  if (!input.empty() && input[0] == 't') throw std::runtime_error("uncaught");  /* an uncaught exception: 134 */
  return example_run(data, size);
}
