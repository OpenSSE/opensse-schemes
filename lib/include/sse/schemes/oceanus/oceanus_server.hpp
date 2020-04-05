#pragma once

#include <sse/schemes/abstractio/awonvm_vector.hpp>
#include <sse/schemes/oceanus/cuckoo.hpp>
#include <sse/schemes/oceanus/oceanus_server_builder.hpp>
#include <sse/schemes/oceanus/types.hpp>

#include <exception>
#include <list>

namespace sse {
namespace oceanus {


template<size_t PAGE_SIZE>
class OceanusServer
{
public:
    using content_type       = data_type<PAGE_SIZE>;
    using content_serializer = OceanusContentSerializer<PAGE_SIZE>;


    OceanusServer(const std::string& db_path);
    ~OceanusServer();

    std::vector<index_type> search(const SearchRequest& req);

    // using content_type = payload_type<PAGE_SIZE>;
    // using content_type = typename
    // OceanusServerBuilder<PAGE_SIZE>::content_type;

    CuckooHashTable<PAGE_SIZE,
                    key_type,
                    content_type,
                    OceanusKeySerializer,
                    content_serializer,
                    OceanusCuckooHasher>
        cuckoo_table;

private:
};

template<size_t PAGE_SIZE>
OceanusServer<PAGE_SIZE>::OceanusServer(const std::string& db_path)
    : cuckoo_table(OceanusServerBuilder<PAGE_SIZE>::first_table_path(db_path),
                   OceanusServerBuilder<PAGE_SIZE>::second_table_path(db_path))
{
    std::cerr << "Oceanus server initialization succeeded!\n";
}

template<size_t PAGE_SIZE>
OceanusServer<PAGE_SIZE>::~OceanusServer()
{
}

template<size_t PAGE_SIZE>
std::vector<index_type> OceanusServer<PAGE_SIZE>::search(
    const SearchRequest& req)
{
    std::vector<index_type> res;


    // const size_t table_size = table1.size();

    // if (table_size != table2.size()) {
    //     throw std::runtime_error("Invalid state (Cuckoo Table Size)");
    // }


    for (size_t i = 0;; i++) {
        std::array<uint8_t, kTableKeySize> prf_out
            = req.prf.prf(reinterpret_cast<uint8_t*>(&i), sizeof(i));


        try {
            content_type val = cuckoo_table.get(prf_out);

            for (auto it = val.begin(); it != val.end(); ++it) {
                res.push_back(*it);
            }
        } catch (const std::exception& e) {
            std::cerr << e.what() << '\n';
            break;
        }
    }
    return res;
}


} // namespace oceanus
} // namespace sse
