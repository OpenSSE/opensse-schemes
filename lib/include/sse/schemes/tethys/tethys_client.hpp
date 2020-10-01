#pragma once


#include <sse/schemes/tethys/details/tethys_utils.hpp>
#include <sse/schemes/tethys/types.hpp>
#include <sse/schemes/utils/rocksdb_wrapper.hpp>

#include <sse/crypto/key.hpp>
#include <sse/crypto/prf.hpp>

#include <array>


namespace sse {
namespace tethys {

template<class ValueDecoder>
class TethysClient
{
public:
    static constexpr size_t kServerBucketSize = ValueDecoder::kPayloadSize;
    using server_bucket_type = std::array<uint8_t, kServerBucketSize>;

    struct KeyedBucketPair
    {
        tethys_core_key_type key;
        size_t               index_0;
        size_t               index_1;
        server_bucket_type   payload_0;
        server_bucket_type   payload_1;
    };

    TethysClient(const std::string&               counter_db_path,
                 const std::string&               stash_path,
                 crypto::Key<kMasterPrfKeySize>&& master_key);


    // we have to specificy templated constructors inside the class definition
    // (they do not have a name that can be 'templated')

    template<class StashDecoder = ValueDecoder>
    TethysClient(const std::string&               counter_db_path,
                 const std::string&               stash_path,
                 StashDecoder&                    stash_decoder,
                 crypto::Key<kMasterPrfKeySize>&& master_key)
        : counter_db(counter_db_path), master_prf(std::move(master_key))
    {
        load_stash(stash_path, stash_decoder);

        std::cerr << "Tethys client initialization succeeded!\n";
        std::cerr << "Stash size: " << stash.size() << "\n";
    }


    SearchRequest search_request(const std::string& keyword,
                                 bool               log_not_found = true) const;

    std::vector<index_type> decode_search_results(
        const SearchRequest&         req,
        std::vector<KeyedBucketPair> bucket_pairs,
        ValueDecoder&                decoder);

private:
    template<class StashDecoder>
    void load_stash(const std::string& stash_path, StashDecoder& stash_decoder);


    std::map<tethys_core_key_type, std::vector<index_type>> stash;
    sophos::RocksDBCounter                                  counter_db;

    master_prf_type master_prf;
};

template<class ValueDecoder>
TethysClient<ValueDecoder>::TethysClient(
    const std::string&               counter_db_path,
    const std::string&               stash_path,
    crypto::Key<kMasterPrfKeySize>&& master_key)
    : counter_db(counter_db_path), master_prf(std::move(master_key))
{
    ValueDecoder stash_decoder;

    load_stash(stash_path, stash_decoder);

    std::cerr << "Tethys client initialization succeeded!\n";
    std::cerr << "Stash size: " << stash.size() << "\n";
}


template<class ValueDecoder>
template<class StashDecoder>
void TethysClient<ValueDecoder>::load_stash(const std::string& stash_path,
                                            StashDecoder&      stash_decoder)
{
    if (utility::is_file(stash_path)) {
        std::ifstream input_stream;

        input_stream.open(stash_path);

        stash = abstractio::deserialize_map<tethys_core_key_type,
                                            std::vector<index_type>,
                                            ValueDecoder>(input_stream,
                                                          stash_decoder);

        input_stream.close();
    }
}

template<class ValueDecoder>

std::vector<index_type> TethysClient<ValueDecoder>::decode_search_results(
    const SearchRequest&         req,
    std::vector<KeyedBucketPair> keyed_bucket_pairs,
    ValueDecoder&                decoder)
{
    std::vector<index_type> results;

    for (const KeyedBucketPair& key_bucket : keyed_bucket_pairs) {
        std::vector<index_type> bucket_res
            = decoder.decode_buckets(key_bucket.key,
                                     key_bucket.payload_0,
                                     key_bucket.index_0,
                                     key_bucket.payload_1,
                                     key_bucket.index_1);

        results.reserve(results.size() + bucket_res.size());
        results.insert(results.end(), bucket_res.begin(), bucket_res.end());


        auto stash_it = stash.find(key_bucket.key);

        if (stash_it != stash.end()) {
            const std::vector<index_type>& stash_res = stash_it->second;
            results.reserve(results.size() + stash_res.size());
            results.insert(results.end(), stash_res.begin(), stash_res.end());
        }
    }

    return results;
}

} // namespace tethys
} // namespace sse