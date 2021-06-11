#pragma once

#include <sse/schemes/abstractio/awonvm_vector.hpp>
#include <sse/schemes/abstractio/kv_serializer.hpp>
#include <sse/schemes/tethys/details/tethys_allocator.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <cstdint>

#include <array>
#include <fstream>
#include <map>
#include <string>
#include <vector>


namespace sse {
namespace tethys {

class EmptyDecoder
{
};

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueDecoder = EmptyDecoder>
class TethysStore
{
public:
    static constexpr size_t kPayloadSize = PAGE_SIZE;
    using payload_type                   = std::array<uint8_t, kPayloadSize>;

    using key_type     = Key;
    using value_type   = T;
    using decoder_type = ValueDecoder;

    using get_buckets_callback_type
        = std::function<void(std::unique_ptr<payload_type>, size_t)>;

    using get_list_callback_type = std::function<void(std::vector<T>)>;

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

    BucketPair<PAGE_SIZE> get_buckets(const Key& key);

    std::vector<T> get_list(const Key& key, ValueDecoder& decoder);

    std::vector<T> get_list(const Key& key);


    void async_get_buckets(const Key& key, get_buckets_callback_type callback);
    void async_get_list(const Key&             key,
                        ValueDecoder&          decoder,
                        get_list_callback_type callback);
    void async_get_list(const Key& key, get_list_callback_type callback);

private:
    void load_stash(const std::string& stash_path, EmptyDecoder& stash_decoder)
    {
        (void)stash_path;
        (void)stash_decoder;
    }

    template<class StashDecoder>
    void load_stash(const std::string& stash_path, StashDecoder& stash_decoder);


    template<class CallbackState>
    void async_get_list_helper(get_list_callback_type callback,
                               CallbackState*         state);

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

// template<size_t PAGE_SIZE,
//          class Key,
//          class T,
//          class TethysHasher,
//          class ValueDecoder>
// template<>
// void TethysStore<PAGE_SIZE, Key, T, TethysHasher, ValueDecoder>::load_stash(
//     const std::string& stash_path,
//     EmptyDecoder&      stash_decoder)
// {
//     // do nothing
// }

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
BucketPair<PAGE_SIZE> TethysStore<PAGE_SIZE,
                                  Key,
                                  T,
                                  TethysHasher,
                                  ValueDecoder>::get_buckets(const Key& key)
{
    details::TethysAllocatorKey tethys_key = TethysHasher()(key);

    BucketPair<PAGE_SIZE> bucket_pair;

    size_t half_graph_size       = table_size / 2;
    size_t remaining_graphs_size = table_size - half_graph_size;

    bucket_pair.index_0 = tethys_key.h[0] % half_graph_size;
    bucket_pair.index_1
        = half_graph_size + tethys_key.h[1] % remaining_graphs_size;

    bucket_pair.payload_0 = table.get(bucket_pair.index_0);
    bucket_pair.payload_1 = table.get(bucket_pair.index_1);

    return bucket_pair;
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

    BucketPair<PAGE_SIZE> buckets    = get_buckets(key);
    std::vector<T>        bucket_res = decode_list(key,
                                            decoder,
                                            buckets.payload_0,
                                            buckets.index_0,
                                            buckets.payload_1,
                                            buckets.index_1);

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

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueDecoder>
template<class CallbackState>
void TethysStore<PAGE_SIZE, Key, T, TethysHasher, ValueDecoder>::
    async_get_list_helper(get_list_callback_type callback, CallbackState* state)
{
    auto bucket_cb = [this, callback, state](
                         std::unique_ptr<payload_type> bucket, size_t index) {
        uint8_t completed = state->completion_counter.fetch_add(1) + 1;

        if (completed == 1) {
            state->index_0  = index;
            state->bucket_0 = std::move(bucket);
        } else if (completed == 2) {
            state->index_1  = index;
            state->bucket_1 = std::move(bucket);


            std::vector<T> stash_res;

            auto stash_it = stash.find(state->key);

            if (stash_it != stash.end()) {
                stash_res = stash_it->second;
            }

            std::vector<T> bucket_res = this->decode_list(state->key,
                                                          state->get_decoder(),
                                                          *(state->bucket_0),
                                                          state->index_0,
                                                          *(state->bucket_1),
                                                          state->index_1);

            bucket_res.reserve(bucket_res.size() + stash_res.size());
            bucket_res.insert(
                bucket_res.end(), stash_res.begin(), stash_res.end());


            delete state;
            callback(bucket_res);
        }
    };


    async_get_buckets(state->key, bucket_cb);
}
template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueDecoder>
void TethysStore<PAGE_SIZE, Key, T, TethysHasher, ValueDecoder>::async_get_list(
    const Key&             key,
    get_list_callback_type callback)
{
    struct CallBackState
    {
        Key                           key;
        std::unique_ptr<payload_type> bucket_0;
        std::unique_ptr<payload_type> bucket_1;
        size_t                        index_0{SIZE_MAX};
        size_t                        index_1{SIZE_MAX};
        std::atomic<uint8_t>          completion_counter{0};
        ValueDecoder                  decoder;

        explicit CallBackState(const Key& k) : key(k){};

        ValueDecoder& get_decoder()
        {
            return decoder;
        }
    };

    CallBackState* state = new CallBackState(key);

    async_get_list_helper<CallBackState>(std::move(callback), state);
}

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class TethysHasher,
         class ValueDecoder>
void TethysStore<PAGE_SIZE, Key, T, TethysHasher, ValueDecoder>::async_get_list(
    const Key&             key,
    ValueDecoder&          decoder,
    get_list_callback_type callback)
{
    struct CallBackState
    {
        Key                           key;
        std::unique_ptr<payload_type> bucket_0;
        std::unique_ptr<payload_type> bucket_1;
        size_t                        index_0{SIZE_MAX};
        size_t                        index_1{SIZE_MAX};
        std::atomic<uint8_t>          completion_counter{0};
        ValueDecoder*                 decoder;

        CallBackState(const Key& k, ValueDecoder& dec)
            : key(k), decoder(&dec){};

        ValueDecoder& get_decoder()
        {
            return *decoder;
        }
    };

    CallBackState* state = new CallBackState(key, decoder);

    async_get_list_helper<CallBackState>(std::move(callback), state);
}

} // namespace tethys
} // namespace sse