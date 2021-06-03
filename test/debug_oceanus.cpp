
#include <sse/schemes/oceanus/oceanus_server.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <sse/crypto/utils.hpp>

using namespace sse::oceanus;

void test_insertion(const size_t n_insertions)
{
    constexpr size_t kPageSize = 4096; // 4 kB

    const std::string path             = "oceanus_test.bin";
    const size_t      n_elts           = n_insertions;
    const double      epsilon          = 0.1;
    const size_t      max_search_depth = 200;


    constexpr size_t kKeySize = sse::crypto::Prf<kTableKeySize>::kKeySize;
    std::array<uint8_t, kKeySize> prf_key_1;
    std::fill(prf_key_1.begin(), prf_key_1.end(), 0x00);
    std::array<uint8_t, kKeySize> prf_key_2;
    std::fill(prf_key_2.begin(), prf_key_2.end(), 0x11);

    sse::crypto::Prf<kTableKeySize> prf_1(
        sse::crypto::Key<kKeySize>(prf_key_1.data()));
    sse::crypto::Prf<kTableKeySize> prf_2(
        sse::crypto::Key<kKeySize>(prf_key_2.data()));


    data_type<kPageSize> pl_1, pl_2;

    const size_t fill_val_1 = 0xABCDEF;
    const size_t fill_val_2 = 0x987654;
    std::fill(pl_1.begin(), pl_1.end(), fill_val_1);
    std::fill(pl_2.begin(), pl_2.end(), fill_val_2);
    size_t actual_insertions = n_insertions / 2;


    if (!sse::utility::is_file(path)) {
        OceanusBuilder<kPageSize> builder(
            path, n_elts, epsilon, max_search_depth);


        std::cout << "Start insertions" << std::endl;
        for (size_t i = 0; i < actual_insertions; i++) {
            std::array<uint8_t, kTableKeySize> prf_out
                = prf_1.prf(reinterpret_cast<uint8_t*>(&i), sizeof(i));

            builder.insert(prf_out, pl_1);
        }

        for (size_t i = 0; i < actual_insertions; i++) {
            std::array<uint8_t, kTableKeySize> prf_out
                = prf_2.prf(reinterpret_cast<uint8_t*>(&i), sizeof(i));

            builder.insert(prf_out, pl_2);
        }
        builder.commit();
        // the builder gets destructed here
    }
    {
        // now construct the real server
        Oceanus<kPageSize> server(path);


        // construct a search request from the PRF
        SearchRequest req_1(std::move(prf_1));

        auto begin = std::chrono::high_resolution_clock::now();

        std::vector<uint64_t> res;

        res = server.search(req_1);

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> time_ms = end - begin;

        std::cout << "Sync read duration: " << time_ms.count() << " ms\n";
        std::cout << 1000 * time_ms.count() / actual_insertions << " mus/elt\n";
        std::cout << 1000 * actual_insertions / time_ms.count() << " elt/s\n\n";

        std::cerr << "Res size: " << res.size() << "\n";
        std::cerr << "Expected: " << actual_insertions * pl_1.size() << "\n";

        for (auto& r : res) {
            if (r != fill_val_1) {
                std::cerr << "Invalid result: " << r << "\n";
            }
        }


        SearchRequest req_2(std::move(prf_2));

        begin = std::chrono::high_resolution_clock::now();

        res = server.search_async(req_2);

        end = std::chrono::high_resolution_clock::now();

        time_ms = end - begin;

        std::cout << "Async read duration: " << time_ms.count() << " ms\n";
        std::cout << 1000 * time_ms.count() / actual_insertions << " mus/elt\n";
        std::cout << 1000 * actual_insertions / time_ms.count() << " elt/s\n\n";

        std::cerr << "Res size: " << res.size() << "\n";
        std::cerr << "Expected: " << actual_insertions * pl_2.size() << "\n";

        for (auto& r : res) {
            if (r != fill_val_2) {
                std::cerr << "Invalid result: " << r << "\n";
            }
        }
    }
}

int main(int /*argc*/, const char** /*argv*/)
{
    sse::crypto::init_crypto_lib();
    test_insertion(1 << (17));
    sse::crypto::cleanup_crypto_lib();

    return 0;
}