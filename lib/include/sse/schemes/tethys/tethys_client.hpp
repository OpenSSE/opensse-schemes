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
    using keyed_bucket_pair_type = KeyedBucketPair<kServerBucketSize>;

    using decrypt_decoder_type
        = encoders::DecryptDecoder<ValueDecoder, kServerBucketSize>;
    static constexpr size_t kDecryptionKeySize = decrypt_decoder_type::kKeySize;

    TethysClient(const std::string&                counter_db_path,
                 const std::string&                stash_path,
                 crypto::Key<kMasterPrfKeySize>&&  master_key,
                 crypto::Key<kDecryptionKeySize>&& decryption_key);


    // we have to specificy templated constructors inside the class definition
    // (they do not have a name that can be 'templated')

    template<class StashDecoder = ValueDecoder>
    TethysClient(const std::string&                counter_db_path,
                 const std::string&                stash_path,
                 StashDecoder&                     stash_decoder,
                 crypto::Key<kMasterPrfKeySize>&&  master_key,
                 crypto::Key<kDecryptionKeySize>&& decryption_key)
        : counter_db(counter_db_path), master_prf(master_key),
          decrypt_decoder(decryption_key)
    {
        load_stash(stash_path, stash_decoder);

        std::cerr << "Tethys client initialization succeeded!\n";
        std::cerr << "Stash size: " << stash.size() << "\n";
    }


    SearchRequest search_request(const std::string& keyword,
                                 bool               log_not_found = true) const;

    std::vector<index_type> decode_search_results(
        const SearchRequest&                req,
        std::vector<keyed_bucket_pair_type> bucket_pairs);

private:
    template<class StashDecoder>
    void load_stash(const std::string& stash_path, StashDecoder& stash_decoder);


    std::map<tethys_core_key_type, std::vector<index_type>> stash;
    sophos::RocksDBCounter                                  counter_db;

    master_prf_type      master_prf;
    decrypt_decoder_type decrypt_decoder;
};

template<class ValueDecoder>
TethysClient<ValueDecoder>::TethysClient(
    const std::string&                counter_db_path,
    const std::string&                stash_path,
    crypto::Key<kMasterPrfKeySize>&&  master_key,
    crypto::Key<kDecryptionKeySize>&& decryption_key)
    : counter_db(counter_db_path), master_prf(master_key),
      decrypt_decoder(decryption_key)
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
    const SearchRequest&                req,
    std::vector<keyed_bucket_pair_type> keyed_bucket_pairs)
{
    std::vector<index_type> results;

    for (const keyed_bucket_pair_type& key_bucket : keyed_bucket_pairs) {
        std::vector<index_type> bucket_res
            = decrypt_decoder.decode_buckets(key_bucket.key,
                                             key_bucket.buckets.payload_0,
                                             key_bucket.buckets.index_0,
                                             key_bucket.buckets.payload_1,
                                             key_bucket.buckets.index_1);

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