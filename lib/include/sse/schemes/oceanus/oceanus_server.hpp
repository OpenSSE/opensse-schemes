#pragma once

#include <sse/schemes/abstractio/awonvm_vector.hpp>
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
    OceanusServer(const std::string& db_path);
    ~OceanusServer();

    std::list<index_type> search(const SearchRequest& req);

    using content_type = typename OceanusServerBuilder<PAGE_SIZE>::content_type;

    abstractio::awonvm_vector<content_type, PAGE_SIZE> table1;
    abstractio::awonvm_vector<content_type, PAGE_SIZE> table2;

private:
};

template<size_t PAGE_SIZE>
OceanusServer<PAGE_SIZE>::OceanusServer(const std::string& db_path)
    : table1(OceanusServerBuilder<PAGE_SIZE>::first_table_path(db_path), false),
      table2(OceanusServerBuilder<PAGE_SIZE>::second_table_path(db_path), false)
{
    if (!table1.is_committed()) {
        throw std::runtime_error("Table 1 not committed");
    }
    if (!table2.is_committed()) {
        throw std::runtime_error("Table 1 not committed");
    }

    std::cerr << "Oceanus server initialization succeeded!\n";
}

template<size_t PAGE_SIZE>
OceanusServer<PAGE_SIZE>::~OceanusServer()
{
}

template<size_t PAGE_SIZE>
std::list<index_type> OceanusServer<PAGE_SIZE>::search(const SearchRequest& req)
{
    std::list<index_type> res;


    const size_t table_size = table1.size();

    if (table_size != table2.size()) {
        throw std::runtime_error("Invalid state (Cuckoo Table Size)");
    }


    for (size_t i = 0;; i++) {
        std::array<uint8_t, kTableKeySize> prf_out
            = req.prf.prf(reinterpret_cast<uint8_t*>(&i), sizeof(i));

        CuckooKey search_key(prf_out);

        // look in the first table
        size_t loc1 = search_key.h[0] % table_size;

        payload_type<PAGE_SIZE> val1 = table1.get(loc1);
        if (match_key<PAGE_SIZE>(val1, prf_out)) {
            // found a value, append it to the results list

            for (auto it = val1.begin() + kOverhead; it != val1.end(); ++it) {
                res.emplace_back(*it);
            }
        } else {
            size_t loc2 = search_key.h[1] % table_size;

            payload_type<PAGE_SIZE> val2 = table2.get(loc2);
            if (match_key<PAGE_SIZE>(val2, prf_out)) {
                // found a value, append it to the results list
                for (auto it = val2.begin() + kOverhead; it != val2.end();
                     ++it) {
                    res.emplace_back(*it);
                }
            } else {
                break;
            }
        }
    }
    return res;
}


} // namespace oceanus
} // namespace sse
