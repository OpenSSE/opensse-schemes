
#include <sse/schemes/oceanus/oceanus_server_builder.hpp>

#include <sse/crypto/utils.hpp>

using namespace sse::oceanus;

void test_insertion(const size_t n_insertions)
{
    constexpr size_t kPageSize = 4096; // 4 kB

    const std::string path             = "oceanus_test.bin";
    const size_t      n_elts           = n_insertions;
    const double      epsilon          = 0.1;
    const size_t      max_search_depth = 200;


    OceanusServerBuilder<kPageSize> builder(
        path, n_elts, epsilon, max_search_depth);

    sse::crypto::Prf<kTableKeySize> prf;
    data_type<kPageSize>            pl;
    std::fill(pl.begin(), pl.end(), 0);

    std::cout << "Start insertions" << std::endl;

    for (size_t i = 0; i < 2 * n_insertions; i++) {
        std::array<uint8_t, kTableKeySize> prf_out
            = prf.prf(reinterpret_cast<uint8_t*>(&i), sizeof(i));

        builder.insert(prf_out, pl);
    }
}

int main(int /*argc*/, const char** /*argv*/)
{
    sse::crypto::init_crypto_lib();
    test_insertion(1 << (17));
    sse::crypto::cleanup_crypto_lib();

    return 0;
}