#pragma once

#include <sse/schemes/pluto/types.hpp>
#include <sse/schemes/tethys/details/tethys_utils.hpp>
#include <sse/schemes/tethys/tethys_store_builder.hpp>

#include <sse/dbparser/json/DBParserJSON.h>

#include <array>

namespace sse {
namespace pluto {

template<class Params>
class PlutoBuilder
{
public:
    using tethys_store_builder_type = tethys::TethysStoreBuilder<
        Params::kPageSize,
        tethys::tethys_core_key_type,
        index_type,
        typename Params::tethys_hasher_type,
        typename Params::tethys_encoder_type,
        typename Params::tethys_stash_encoder_type>;

    static constexpr size_t kTethysMaxListSize
        = tethys_store_builder_type::kMaxListSize;

    using ht_builder_type = typename Params::ht_builder_type;


    using ht_builder_param_type = typename ht_builder_type::param_type;


    static constexpr size_t kEncryptionKeySize
        = Params::tethys_encoder_type::kKeySize;
    static constexpr size_t kMasterPrfKeySize = tethys::kMasterPrfKeySize;

    PlutoBuilder(size_t                                  n_elts,
                 const tethys::TethysStoreBuilderParam&  tethys_builder_param,
                 const ht_builder_param_type&            ht_builder_param,
                 crypto::Key<kMasterPrfKeySize>&&        master_key,
                 std::array<uint8_t, kEncryptionKeySize> encryption_key);

    PlutoBuilder(PlutoBuilder&&) = default;

    void build();

    void insert_list(const std::string&         keyword,
                     const std::list<uint64_t>& indexes);
    bool load_inverted_index(const std::string& path);

private:
    tethys_store_builder_type tethys_store_builder;
    ht_builder_type           ht_builder;

    tethys::master_prf_type master_prf;

    typename Params::tethys_encoder_type tethys_encryption_encoder;

    const size_t n_elts;
    size_t       incomplete_lists{0};
    size_t       complete_lists{0};
    size_t       large_lists{0};

    size_t incomplete_lists_entries{0};
    size_t complete_lists_entries{0};
};

template<class Params>
PlutoBuilder<Params>::PlutoBuilder(
    size_t                                  n_elts,
    const tethys::TethysStoreBuilderParam&  tethys_builder_param,
    const ht_builder_param_type&            ht_builder_param,
    crypto::Key<kMasterPrfKeySize>&&        master_key,
    std::array<uint8_t, kEncryptionKeySize> encryption_key)
    : tethys_store_builder(tethys_builder_param), ht_builder(ht_builder_param),
      master_prf(std::move(master_key)),
      tethys_encryption_encoder(encryption_key), n_elts(n_elts)
{
}


template<class Params>
void PlutoBuilder<Params>::build()
{
    logger::logger()->info("Start building Pluto");


    logger::logger()->info("Filling the HT with empty blocks");

    // for the security of the scheme, because we do not want to leak the
    // number of full blocks, we have to insert a dummy block in the hash
    // table
    const size_t n_full_blocks = 1 + ((n_elts - 1) / Params::kPlutoListLength);

    typename Params::ht_value_type v = {0x00};

    for (size_t i = complete_lists; i < n_full_blocks; i++) {
        tethys::tethys_core_key_type rand_key
            = sse::crypto::random_bytes<uint8_t, tethys::kTethysCoreKeySize>();
        ht_builder.insert(rand_key, v);
    }

    logger::logger()->info("Commiting the cuckoo table");

    ht_builder.commit();

    logger::logger()->info("Finished commiting the cuckoo table");


    typename Params::tethys_stash_encoder_type stash_encoder;

    logger::logger()->info("Building the Tethys store");

    tethys_store_builder.build(tethys_encryption_encoder, stash_encoder);

    logger::logger()->info("Tethys store built");
}


template<class Params>
void PlutoBuilder<Params>::insert_list(const std::string&         keyword,
                                       const std::list<uint64_t>& indexes)
{
    size_t counter       = 0;
    size_t block_counter = 1;

    std::vector<uint64_t> block;
    block.reserve(Params::kPlutoListLength);

    std::array<uint8_t, tethys::kSearchTokenSize> keyword_token
        = master_prf.prf(keyword);

    for (uint64_t id : indexes) {
        counter++;
        block.push_back(id);

        if (block.size() == Params::kPlutoListLength) {
            complete_lists++;
            complete_lists_entries += block.size();
            // generate the core key
            tethys::tethys_core_key_type key = tethys::details::derive_core_key(
                keyword_token, block_counter);

            // transform the list an array
            typename Params::ht_value_type v = {0x00};
            std::copy(block.begin(), block.end(), v.begin());

            // insert the list
            ht_builder.insert(key, v);

            block_counter++;
            block.clear();
            block.reserve(
                Params::kPlutoListLength); // clear() does not guaranty the
                                           // capacity to stay the same
        }
    }

    if (block_counter > 1) {
        large_lists++;
    }
    // take care of the incomplete block

    if (block.size() > 0) {
        incomplete_lists++;
        incomplete_lists_entries += block.size();

        // generate the key
        tethys::tethys_core_key_type key
            = tethys::details::derive_core_key(keyword_token, 0);


        // insert the list
        tethys_store_builder.insert_list(key, block);
    }
}


template<class Params>
bool PlutoBuilder<Params>::load_inverted_index(const std::string& path)
{
    try {
        dbparser::DBParserJSON parser(path.c_str());

        std::atomic_size_t kw_counter(0);
        std::atomic_size_t entries_counter(0);

        auto add_list_callback
            = [this, &kw_counter, &entries_counter](
                  const std::string& kw, const std::list<unsigned>& docs) {
                  this->insert_list(
                      kw, std::list<index_type>(docs.begin(), docs.end()));
                  kw_counter++;
                  size_t size = docs.size();

                  entries_counter += size;

                  if ((kw_counter % 10000) == 0) {
                      logger::logger()->info(
                          "Loading: {} keywords processed, {} entries",
                          kw_counter,
                          entries_counter);
                  }
              };


        parser.addCallbackList(add_list_callback);

        parser.parse();

        logger::logger()->info("Loading: {} keywords processed, {} entries",
                               kw_counter,
                               entries_counter);

        logger::logger()->info(
            "Loading: {} complete blocks for {} keywords, {} entries",
            complete_lists,
            large_lists,
            complete_lists_entries);
        logger::logger()->info("Loading: {} incomplete blocks, {} entries",
                               incomplete_lists,
                               incomplete_lists_entries);

        return true;
    } catch (std::exception& e) {
        logger::logger()->error("Failed to load file " + path + ": "
                                + e.what());
        return false;
    }
    return false;
}


} // namespace pluto
} // namespace sse