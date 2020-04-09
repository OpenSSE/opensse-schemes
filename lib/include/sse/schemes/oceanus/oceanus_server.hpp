#pragma once

#include <sse/schemes/abstractio/awonvm_vector.hpp>
#include <sse/schemes/oceanus/cuckoo.hpp>
#include <sse/schemes/oceanus/oceanus_server_builder.hpp>
#include <sse/schemes/oceanus/types.hpp>

#include <exception>
#include <future>
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
    std::vector<index_type> search_async(const SearchRequest& req);

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

    for (size_t i = 0;; i++) {
        // generate the table key
        std::array<uint8_t, kTableKeySize> prf_out
            = req.prf.prf(reinterpret_cast<uint8_t*>(&i), sizeof(i));

        try {
            // query the table
            content_type val = cuckoo_table.get(prf_out);

            for (auto it = val.begin(); it != val.end(); ++it) {
                // 'deserialize' the results
                res.push_back(*it);
            }
        } catch (const std::out_of_range& e) {
            std::cerr << e.what() << '\n';
            break;
        }
    }
    return res;
}


template<size_t PAGE_SIZE>
std::vector<index_type> OceanusServer<PAGE_SIZE>::search_async(
    const SearchRequest& req)
{
    cuckoo_table.use_direct_IO(true);

    std::vector<index_type> res;

    std::atomic_bool   stop_flag(false);
    std::atomic_size_t submitted_queries(0);
    std::atomic_size_t completed_queries(0);

    std::promise<void> notifier;
    std::future<void>  notifier_future = notifier.get_future();

    std::mutex mutex;

    auto callback = [&notifier,
                     &res,
                     &stop_flag,
                     &submitted_queries,
                     &completed_queries,
                     &mutex](std::experimental::optional<content_type> val) {
        if (val.has_value()) {
            // the callback can be called from two different threads, so we need
            // a lock here
            const std::lock_guard<std::mutex> lock(mutex);
            for (auto it = val.value().begin(); it != val.value().end(); ++it) {
                // 'deserialize' the results
                res.push_back(*it);
            }
        } else {
            // value not found, any new query is useless
            stop_flag.store(true);
        }
        size_t query_count = completed_queries.fetch_add(1) + 1;

        if ((query_count == submitted_queries) && stop_flag) {
            notifier.set_value();
        }
    };


    for (size_t i = 0; !stop_flag; i++) {
        // generate the table key
        std::array<uint8_t, kTableKeySize> prf_out
            = req.prf.prf(reinterpret_cast<uint8_t*>(&i), sizeof(i));

        cuckoo_table.async_get(prf_out, callback);
        submitted_queries.fetch_add(1);
    }

    // wait for completion of the queries
    notifier_future.get();


    return res;
}


} // namespace oceanus
} // namespace sse
