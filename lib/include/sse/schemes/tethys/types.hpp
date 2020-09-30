#pragma once

#include <sse/crypto/prf.hpp>

namespace sse {
namespace tethys {

constexpr size_t kTethysCoreKeySize
    = 16; // 128 bits key that will be splitted in two 64 bits bucket indices
using tethys_core_key_type = std::array<uint8_t, kTethysCoreKeySize>;


constexpr size_t kSearchTokenSize = 16; // 128 bits tokens
using search_token_type           = std::array<uint8_t, kSearchTokenSize>;


using master_prf_type = crypto::Prf<kSearchTokenSize>;

constexpr size_t kMasterPrfKeySize = master_prf_type::kKeySize;


} // namespace tethys
} // namespace sse
