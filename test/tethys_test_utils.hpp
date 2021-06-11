#include <sse/schemes/tethys/tethys_store_builder.hpp>
#include <sse/schemes/utils/utils.hpp>


namespace sse {
namespace tethys {
namespace test {


constexpr size_t kPageSize     = 4096; // 4 kB
constexpr size_t kTableKeySize = 16;   // 128 bits table keys
using key_type                 = std::array<uint8_t, kTableKeySize>;
} // namespace test
} // namespace tethys
} // namespace sse