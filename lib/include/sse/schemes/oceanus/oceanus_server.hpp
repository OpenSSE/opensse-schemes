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

    using get_callback_type
        = std::function<void(std::experimental::optional<content_type>)>;


    OceanusServer(const std::string& db_path);
    ~OceanusServer();

    data_type<PAGE_SIZE> get(const std::array<uint8_t, kTableKeySize>& ht_key);
    void async_get(const std::array<uint8_t, kTableKeySize>& ht_key,
                   get_callback_type                         callback);

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
    : cuckoo_table(db_path)
{
    std::cerr << "Oceanus server initialization succeeded!\n";
}

template<size_t PAGE_SIZE>
OceanusServer<PAGE_SIZE>::~OceanusServer()
{
}

template<size_t PAGE_SIZE>
data_type<PAGE_SIZE> OceanusServer<PAGE_SIZE>::get(
    const std::array<uint8_t, kTableKeySize>& ht_key)
{
    // std::vector<index_type> res;


    // query the table
    content_type val = cuckoo_table.get(ht_key);

    // for (auto it = val.begin(); it != val.end(); ++it) {
    //     // 'deserialize' the results
    //     res.push_back(*it);
    // }
    return val;
}


template<size_t PAGE_SIZE>
void OceanusServer<PAGE_SIZE>::async_get(
    const std::array<uint8_t, kTableKeySize>& ht_key,
    get_callback_type                         callback)
{
    cuckoo_table.use_direct_IO(true);

    cuckoo_table.async_get(ht_key, callback);
}

// template<size_t PAGE_SIZE>
// std::vector<index_type> OceanusServer<PAGE_SIZE>::search_async(
//     const SearchRequest& req)
// {
//     cuckoo_table.use_direct_IO(true);

//     std::vector<index_type> res;

//     std::atomic<bool>  stop_flag(false);
//     std::atomic_size_t submitted_queries(0);
//     std::atomic_size_t completed_queries(0);

//     std::promise<void> notifier;
//     std::future<void>  notifier_future = notifier.get_future();

//     std::mutex mutex;

//     auto callback = [&notifier,
//                      &res,
//                      &stop_flag,
//                      &submitted_queries,
//                      &completed_queries,
//                      &mutex](std::experimental::optional<content_type> val) {
//         if (val.has_value()) {
//             // the callback can be called from two different threads, so
//             // we need a lock here
//             const std::lock_guard<std::mutex> lock(mutex);
//             for (auto it = val.value().begin(); it != val.value().end();
//             ++it) {
//                 // 'deserialize' the results
//                 res.push_back(*it);
//             }
//         } else {
//             // value not found, any new query is useless
//             stop_flag.store(true);
//         }
//         size_t query_count = completed_queries.fetch_add(1) + 1;

//         if ((query_count == submitted_queries) && stop_flag) {
//             notifier.set_value();
//         }
//     };


//     for (size_t i = 0; !stop_flag; i++) {
//         // generate the table key
//         std::array<uint8_t, kTableKeySize> prf_out
//             = req.prf.prf(reinterpret_cast<uint8_t*>(&i), sizeof(i));

//         cuckoo_table.async_get(prf_out, callback);
//         submitted_queries.fetch_add(1);
//     }

//     // wait for completion of the queries
//     notifier_future.get();


//     return res;
// }


} // namespace oceanus
} // namespace sse
