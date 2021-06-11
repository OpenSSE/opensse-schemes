#pragma once

#include <sse/schemes/pluto/pluto_server.hpp>
#include <sse/schemes/pluto/types.hpp>
#include <sse/schemes/tethys/details/tethys_utils.hpp>
#include <sse/schemes/tethys/tethys_client.hpp>
#include <sse/schemes/tethys/types.hpp>

#include <array>

namespace sse {
namespace pluto {


template<class TethysValueDecoder>
class PlutoClient
{
public:
    static constexpr size_t kServerBucketSize
        = TethysValueDecoder::kEncodedPayloadSize;
    using keyed_bucket_pair_type = tethys::KeyedBucketPair<kServerBucketSize>;

    using decrypt_decoder_type
        = tethys::encoders::DecryptDecoder<TethysValueDecoder,
                                           kServerBucketSize>;
    static constexpr size_t kDecryptionKeySize = decrypt_decoder_type::kKeySize;

    using stash_type
        = std::map<tethys::tethys_core_key_type, std::vector<index_type>>;

    PlutoClient(const std::string&                       stash_path,
                crypto::Key<tethys::kMasterPrfKeySize>&& master_key,
                std::array<uint8_t, kDecryptionKeySize>  decryption_key);


    // we have to specificy templated constructors inside the class definition
    // (they do not have a name that can be 'templated')

    template<class StashDecoder = TethysValueDecoder>
    PlutoClient(const std::string&                       stash_path,
                StashDecoder&                            stash_decoder,
                crypto::Key<tethys::kMasterPrfKeySize>&& master_key,
                std::array<uint8_t, kDecryptionKeySize>  decryption_key)
        : master_prf(std::move(master_key)), decrypt_decoder(decryption_key)
    {
        load_stash(stash_path, stash_decoder);

        std::cerr << "Pluto client initialization succeeded!\n";
        std::cerr << "Stash size: " << stash.size() << "\n";
    }


    SearchRequest search_request(const std::string& keyword) const;

    std::vector<index_type> decode_search_results(
        const SearchRequest&                    req,
        const SearchResponse<kServerBucketSize> response);

private:
    template<class TethysStashDecoder>
    void load_stash(const std::string&  stash_path,
                    TethysStashDecoder& stash_decoder);

    stash_type stash;

    tethys::master_prf_type master_prf;
    decrypt_decoder_type    decrypt_decoder;
};


template<class TethysValueDecoder>
PlutoClient<TethysValueDecoder>::PlutoClient(
    const std::string&                       stash_path,
    crypto::Key<tethys::kMasterPrfKeySize>&& master_key,
    std::array<uint8_t, kDecryptionKeySize>  decryption_key)
    : master_prf(std::move(master_key)), decrypt_decoder(decryption_key)
{
    TethysValueDecoder stash_decoder;

    load_stash(stash_path, stash_decoder);

    std::cerr << "Pluto client initialization succeeded!\n";
    std::cerr << "Stash size: " << stash.size() << "\n";
}


template<class TethysValueDecoder>
template<class TethysStashDecoder>
void PlutoClient<TethysValueDecoder>::load_stash(
    const std::string&  stash_path,
    TethysStashDecoder& stash_decoder)
{
    if (utility::is_file(stash_path)) {
        std::ifstream input_stream;

        input_stream.open(stash_path);

        stash = abstractio::deserialize_map<tethys::tethys_core_key_type,
                                            std::vector<index_type>,
                                            TethysValueDecoder>(input_stream,
                                                                stash_decoder);

        input_stream.close();
    }
}

template<class TethysValueDecoder>
SearchRequest PlutoClient<TethysValueDecoder>::search_request(
    const std::string& keyword) const
{
    SearchRequest sr;
    sr.search_token = master_prf.prf(keyword);

    return sr;
}

template<class TethysValueDecoder>
std::vector<index_type> PlutoClient<TethysValueDecoder>::decode_search_results(
    const SearchRequest&                    req,
    const SearchResponse<kServerBucketSize> response)
{
    // first get the results stored in Tethys
    tethys::SearchRequest   treq = {req.search_token, 1};
    std::vector<index_type> results
        = tethys::TethysClient<TethysValueDecoder>::decode_search_results(
            treq, {response.tethys_bucket_pair}, stash, decrypt_decoder);

    // and append the results from the hash table
    results.reserve(results.size() + response.complete_lists.size());
    results.insert(results.end(),
                   response.complete_lists.begin(),
                   response.complete_lists.end());

    return results;
}
} // namespace pluto
} // namespace sse