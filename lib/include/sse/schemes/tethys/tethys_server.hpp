#pragma once


#include <sse/schemes/tethys/details/tethys_utils.hpp>
#include <sse/schemes/tethys/tethys_store.hpp>
#include <sse/schemes/tethys/types.hpp>
#include <sse/schemes/utils/rocksdb_wrapper.hpp>

#include <sse/crypto/key.hpp>
#include <sse/crypto/prf.hpp>

#include <array>


namespace sse {
namespace tethys {


template<size_t PAGE_SIZE>
using tethys_server_store_type = TethysStore<PAGE_SIZE,
                                             tethys_core_key_type,
                                             index_type,
                                             IdentityHasher,
                                             EmptyDecoder>;

template<class Store>
class TethysServer
{
public:
    static constexpr size_t kServerBucketSize = Store::kPayloadSize;
    using keyed_bucket_pair_type = KeyedBucketPair<kServerBucketSize>;

    explicit TethysServer(const std::string& store_path);

    std::vector<keyed_bucket_pair_type> search(
        const SearchRequest& search_request);

private:
    Store tethys_store;
};

template<class Store>
TethysServer<Store>::TethysServer(const std::string& store_path)
    : tethys_store(store_path, "")
{
}

template<class Store>
std::vector<typename TethysServer<Store>::keyed_bucket_pair_type> TethysServer<
    Store>::search(const SearchRequest& search_request)
// auto TethysServer<Store>::search(const search_token_type& search_token)
// -> std::vector<keyed_bucket_pair_type>
{
    std::vector<keyed_bucket_pair_type> bucket_pairs;

    for (uint32_t i = 0; i < search_request.block_count; i++) {
        // derive the key from the search token in counter mode
        tethys_core_key_type key
            = details::derive_core_key(search_request.search_token, i);


        BucketPair<kServerBucketSize> buckets = tethys_store.get_buckets(key);

        keyed_bucket_pair_type keyed_buckets{key, buckets};

        bucket_pairs.push_back(keyed_buckets);
    }


    return bucket_pairs;
}


} // namespace tethys
} // namespace sse
