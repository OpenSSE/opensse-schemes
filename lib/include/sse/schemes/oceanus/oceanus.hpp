#pragma once

#include <sse/schemes/abstractio/awonvm_vector.hpp>
#include <sse/schemes/oceanus/cuckoo.hpp>
#include <sse/schemes/oceanus/types.hpp>

#include <exception>
#include <future>
#include <list>


// Oceanus is a wrapper around a cuckoo table with parameters adapted for the
// use in the SSE setting: large random keys, data corresponding to a block of
// 64 bits document indices, ...


namespace sse {
namespace oceanus {


struct OceanusKeySerializer
{
    static constexpr size_t serialization_length()
    {
        return kTableKeySize;
    }
    void serialize(const key_type& key, uint8_t* buffer)
    {
        memcpy(buffer, key.data(), kTableKeySize);
    }
};

struct OceanusCuckooHasher
{
    CuckooKey operator()(const key_type& key)
    {
        CuckooKey ck;
        static_assert(sizeof(ck.h) == sizeof(key_type),
                      "Invalid source key size");

        memcpy(ck.h, key.data(), sizeof(ck.h));

        return ck;
    }
};

template<size_t PAGE_SIZE>
struct OceanusContentSerializer
{
    static constexpr size_t serialization_length()
    {
        return PAGE_SIZE - kOverhead * sizeof(index_type);
    }
    void serialize(const data_type<PAGE_SIZE>& value, uint8_t* buffer)
    {
        assert(value.size() * sizeof(typename data_type<PAGE_SIZE>::value_type)
               == serialization_length());
        memcpy(buffer,
               value.data(),
               value.size()
                   * sizeof(typename data_type<PAGE_SIZE>::value_type));
    }

    data_type<PAGE_SIZE> deserialize(const uint8_t* buffer)
    {
        data_type<PAGE_SIZE> res;
        memcpy(res.data(),
               buffer,
               res.size() * sizeof(typename data_type<PAGE_SIZE>::value_type));

        return res;
    }
};


template<size_t PAGE_SIZE>
class OceanusBuilder
{
public:
    using content_type       = data_type<PAGE_SIZE>;
    using content_serializer = OceanusContentSerializer<PAGE_SIZE>;

    OceanusBuilder(const std::string& db_path,
                   size_t             max_n_elements,
                   double             epsilon,
                   size_t             max_search_depth);
    ~OceanusBuilder();


    void insert(const std::array<uint8_t, kTableKeySize>& key,
                const data_type<PAGE_SIZE>&               value);

    void commit();


private:
    static CuckooBuilderParam make_cuckoo_builder_params(
        const std::string& base_path,
        size_t             max_n_elements,
        double             epsilon,
        size_t             max_search_depth)
    {
        CuckooBuilderParam params;
        params.value_file_path   = tmp_data_path(base_path);
        params.cuckoo_table_path = base_path;
        params.epsilon           = epsilon;
        params.max_n_elements    = max_n_elements;
        params.max_search_depth  = max_search_depth;

        return params;
    }

    static std::string tmp_data_path(std::string path)
    {
        return path.append(".tmp");
    }

    CuckooBuilderParam cuckoo_builder_params;

    CuckooBuilder<PAGE_SIZE,
                  key_type,
                  content_type,
                  OceanusKeySerializer,
                  content_serializer,
                  OceanusCuckooHasher>
        cuckoo_builder;
};


template<size_t PAGE_SIZE>
OceanusBuilder<PAGE_SIZE>::OceanusBuilder(const std::string& db_path,
                                          size_t             max_n_elements,
                                          double             epsilon,
                                          size_t             max_search_depth)
    : cuckoo_builder_params(make_cuckoo_builder_params(db_path,
                                                       max_n_elements,
                                                       epsilon,
                                                       max_search_depth)),
      cuckoo_builder(cuckoo_builder_params)
{
}

template<size_t PAGE_SIZE>
OceanusBuilder<PAGE_SIZE>::~OceanusBuilder()
{
    commit();
}


template<size_t PAGE_SIZE>
void OceanusBuilder<PAGE_SIZE>::commit()
{
    cuckoo_builder.commit();
}

template<size_t PAGE_SIZE>
void OceanusBuilder<PAGE_SIZE>::insert(
    const std::array<uint8_t, kTableKeySize>& key,
    const data_type<PAGE_SIZE>&               value)
{
    cuckoo_builder.insert(key, value);
}


template<size_t PAGE_SIZE>
class Oceanus
{
public:
    using content_type       = data_type<PAGE_SIZE>;
    using content_serializer = OceanusContentSerializer<PAGE_SIZE>;

    using get_callback_type
        = std::function<void(std::experimental::optional<content_type>)>;


    explicit Oceanus(const std::string& db_path);
    ~Oceanus();

    data_type<PAGE_SIZE> get(const std::array<uint8_t, kTableKeySize>& ht_key);
    void async_get(const std::array<uint8_t, kTableKeySize>& ht_key,
                   get_callback_type                         callback);

    // using content_type = payload_type<PAGE_SIZE>;
    // using content_type = typename
    // OceanusBuilder<PAGE_SIZE>::content_type;

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
Oceanus<PAGE_SIZE>::Oceanus(const std::string& db_path) : cuckoo_table(db_path)
{
    std::cerr << "Oceanus server initialization succeeded!\n";
}

template<size_t PAGE_SIZE>
Oceanus<PAGE_SIZE>::~Oceanus()
{
}

template<size_t PAGE_SIZE>
data_type<PAGE_SIZE> Oceanus<PAGE_SIZE>::get(
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
void Oceanus<PAGE_SIZE>::async_get(
    const std::array<uint8_t, kTableKeySize>& ht_key,
    get_callback_type                         callback)
{
    cuckoo_table.use_direct_IO(true);

    cuckoo_table.async_get(ht_key, callback);
}

// template<size_t PAGE_SIZE>
// std::vector<index_type> Oceanus<PAGE_SIZE>::search_async(
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
