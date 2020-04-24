#pragma once

#include <sse/schemes/abstractio/awonvm_vector.hpp>
#include <sse/schemes/abstractio/kv_serializer.hpp>
#include <sse/schemes/tethys/details/tethys_allocator.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <array>
#include <fstream>
#include <map>
#include <string>
#include <vector>


namespace sse {
namespace tethys {

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueDecoder>
class TethysStore
{
public:
    static constexpr size_t kPayloadSize = PAGE_SIZE;
    using payload_type                   = std::array<uint8_t, kPayloadSize>;

    using get_buckets_callback_type
        = std::function<void(std::unique_ptr<payload_type>, size_t)>;

    TethysStore(const std::string& table_path, const std::string& stash_path);

    // we have to specificy templated constructors inside the class definition
    // (they do not have a name that can be 'templated')

    template<class StashDecoder = ValueDecoder>
    TethysStore(const std::string& table_path,
                const std::string& stash_path,
                StashDecoder&      stash_decoder)
        : table(table_path, false)
    {
        if (!table.is_committed()) {
            throw std::runtime_error("Table not committed");
        }
        table_size = table.size();

        load_stash(stash_path, stash_decoder);

        std::cerr << "Tethys storage initialization succeeded!\n";
        std::cerr << "Tethys table size: " << table_size << "\n";
        std::cerr << "Stash size: " << stash.size() << "\n";
    }

    void use_direct_IO(bool flag);

    static std::vector<T> decode_list(const Key&          key,
                                      ValueDecoder&       decoder,
                                      const payload_type& bucket_0,
                                      size_t              bucket_0_index,
                                      const payload_type& bucket_1,
                                      size_t              bucket_1_index);
    static std::vector<T> decode_list(const Key&          key,
                                      const payload_type& bucket_0,
                                      size_t              bucket_0_index,
                                      const payload_type& bucket_1,
                                      size_t              bucket_1_index);

    void get_buckets(const Key&    key,
                     payload_type& bucket_0,
                     size_t&       bucket_0_index,
                     payload_type& bucket_1,
                     size_t&       bucket_1_index);

    std::vector<T> get_list(const Key& key, ValueDecoder& decoder);

    std::vector<T> get_list(const Key& key);


    void async_get_buckets(const Key& key, get_buckets_callback_type callback);

private:
    template<class StashDecoder>
    void load_stash(const std::string& stash_path, StashDecoder& stash_decoder);

    using table_type = abstractio::awonvm_vector<payload_type, PAGE_SIZE>;
    table_type table;

    size_t                        table_size;
    std::map<Key, std::vector<T>> stash;
};

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueDecoder>
TethysStore<PAGE_SIZE, Key, T, TethysHasher, ValueDecoder>::TethysStore(
    const std::string& table_path,
    const std::string& stash_path)
    : table(table_path, false)
{
    if (!table.is_committed()) {
        throw std::runtime_error("Table not committed");
    }
    table_size = table.size();

    ValueDecoder stash_decoder;

    load_stash(stash_path, stash_decoder);

    std::cerr << "Tethys storage initialization succeeded!\n";
    std::cerr << "Tethys table size: " << table_size << "\n";
    std::cerr << "Stash size: " << stash.size() << "\n";
}

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueDecoder>
template<class StashDecoder>
void TethysStore<PAGE_SIZE, Key, T, TethysHasher, ValueDecoder>::load_stash(
    const std::string& stash_path,
    StashDecoder&      stash_decoder)
{
    if (utility::is_file(stash_path)) {
        std::ifstream input_stream;

        input_stream.open(stash_path);

        stash = abstractio::deserialize_map<Key, std::vector<T>, ValueDecoder>(
            input_stream, stash_decoder);

        input_stream.close();
    }
}

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueDecoder>
void TethysStore<PAGE_SIZE, Key, T, TethysHasher, ValueDecoder>::use_direct_IO(
    bool flag)
{
    table.set_use_direct_access(flag);
}

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueDecoder>
std::vector<T> TethysStore<PAGE_SIZE, Key, T, TethysHasher, ValueDecoder>::
    decode_list(const Key&          key,
                ValueDecoder&       decoder,
                const payload_type& bucket_0,
                size_t              bucket_0_index,
                const payload_type& bucket_1,
                size_t              bucket_1_index)
{
    return decoder.decode_buckets(
        key, bucket_0, bucket_0_index, bucket_1, bucket_1_index);
}

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueDecoder>
std::vector<T> TethysStore<PAGE_SIZE, Key, T, TethysHasher, ValueDecoder>::
    decode_list(const Key&          key,
                const payload_type& bucket_0,
                size_t              bucket_0_index,
                const payload_type& bucket_1,
                size_t              bucket_1_index)
{
    ValueDecoder decoder;

    return decoder.decode_buckets(
        key, bucket_0, bucket_0_index, bucket_1, bucket_1_index);
}

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueDecoder>
void TethysStore<PAGE_SIZE, Key, T, TethysHasher, ValueDecoder>::get_buckets(
    const Key&    key,
    payload_type& bucket_0,
    size_t&       bucket_0_index,
    payload_type& bucket_1,
    size_t&       bucket_1_index)
{
    details::TethysAllocatorKey tethys_key = TethysHasher()(key);

    size_t half_graph_size       = table_size / 2;
    size_t remaining_graphs_size = table_size - half_graph_size;

    bucket_0_index = tethys_key.h[0] % half_graph_size;
    bucket_1_index = half_graph_size + tethys_key.h[1] % remaining_graphs_size;

    bucket_0 = table.get(bucket_0_index);
    bucket_1 = table.get(bucket_1_index);
}

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueDecoder>
std::vector<T> TethysStore<PAGE_SIZE, Key, T, TethysHasher, ValueDecoder>::
    get_list(const Key& key, ValueDecoder& decoder)
{
    std::vector<T> stash_res;

    auto stash_it = stash.find(key);

    if (stash_it != stash.end()) {
        stash_res = stash_it->second;
    }

    payload_type bucket_0, bucket_1;
    size_t       index_0, index_1;

    get_buckets(key, bucket_0, index_0, bucket_1, index_1);
    std::vector<T> bucket_res
        = decode_list(key, decoder, bucket_0, index_0, bucket_1, index_1);

    bucket_res.reserve(bucket_res.size() + stash_res.size());
    bucket_res.insert(bucket_res.end(), stash_res.begin(), stash_res.end());

    return bucket_res;
}

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueDecoder>
std::vector<T> TethysStore<PAGE_SIZE, Key, T, TethysHasher, ValueDecoder>::
    get_list(const Key& key)
{
    ValueDecoder decoder;
    return get_list(key, decoder);
}


template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueDecoder>
void TethysStore<PAGE_SIZE, Key, T, TethysHasher, ValueDecoder>::
    async_get_buckets(const Key& key, get_buckets_callback_type callback)
{
    details::TethysAllocatorKey tethys_key = TethysHasher()(key);

    size_t half_graph_size       = table_size / 2;
    size_t remaining_graphs_size = table_size - half_graph_size;

    size_t bucket_0_index = tethys_key.h[0] % half_graph_size;
    size_t bucket_1_index
        = half_graph_size + tethys_key.h[1] % remaining_graphs_size;


    auto bucket_0_cb
        = [bucket_0_index, callback](std::unique_ptr<payload_type> bucket) {
              callback(std::move(bucket), bucket_0_index);
          };

    auto bucket_1_cb
        = [bucket_1_index, callback](std::unique_ptr<payload_type> bucket) {
              callback(std::move(bucket), bucket_1_index);
          };


    using GetRequest = typename table_type::GetRequest;
    table.async_gets({GetRequest(bucket_0_index, bucket_0_cb),
                      GetRequest(bucket_1_index, bucket_1_cb)});
}


} // namespace tethys
} // namespace sse