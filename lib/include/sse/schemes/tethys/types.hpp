#pragma once

#include <sse/crypto/prf.hpp>

namespace sse {
namespace tethys {


constexpr size_t kIdSize = 16; // 128 bits ids
using id_type            = std::array<uint8_t, kIdSize>;

using id_prf_type = crypto::Prf<kIdSize>;

constexpr size_t kSearchTokenSize = id_prf_type::kKeySize;

using master_prf_type = crypto::Prf<kSearchTokenSize>;

constexpr size_t kMasterPrfKeySize = master_prf_type::kKeySize;


} // namespace tethys
} // namespace sse
