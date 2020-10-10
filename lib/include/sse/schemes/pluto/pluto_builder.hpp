#pragma once

#include <sse/schemes/oceanus/cuckoo.hpp>
#include <sse/schemes/oceanus/oceanus_server_builder.hpp>
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
    // = tethys::TethysSBuilder<Params::kPageSize,
    //                         Params::tethys_inner_value_encoder_type,
    //                         Params::stash_encoder_type,
    //                         Params::tethys_hasher_type>;

    static constexpr size_t kTethysMaxListSize
        = tethys_store_builder_type::kMaxListSize;

    using cuckoo_builder_type
        = oceanus::CuckooBuilder<Params::kPageSize,
                                 tethys::tethys_core_key_type,
                                 typename Params::cuckoo_value_type,
                                 PlutoKeySerializer,
                                 PlutoValueSerializer<Params>,
                                 PlutoCuckooHasher>;


    static constexpr size_t kEncryptionKeySize
        = Params::tethys_encoder_type::kKeySize;
    static constexpr size_t kMasterPrfKeySize = tethys::kMasterPrfKeySize;

    PlutoBuilder(const tethys::TethysStoreBuilderParam&  tethys_builder_param,
                 const oceanus::CuckooBuilderParam&      cuckoo_builder_param,
                 crypto::Key<kMasterPrfKeySize>&&        master_key,
                 std::array<uint8_t, kEncryptionKeySize> encryption_key);

    PlutoBuilder(PlutoBuilder&&) = default;

    void build();

    void insert_list(const std::string&         keyword,
                     const std::list<uint64_t>& indexes);
    bool load_inverted_index(const std::string& path);

private:
    tethys_store_builder_type tethys_store_builder;
    cuckoo_builder_type       cuckoo_builder;

    tethys::master_prf_type master_prf;

    typename Params::tethys_encoder_type tethys_encryption_encoder;

    size_t incomplete_lists{0};
    size_t complete_lists{0};
    size_t large_lists{0};

    size_t incomplete_lists_entries{0};
    size_t complete_lists_entries{0};
};

template<class Params>
PlutoBuilder<Params>::PlutoBuilder(
    const tethys::TethysStoreBuilderParam&  tethys_builder_param,
    const oceanus::CuckooBuilderParam&      cuckoo_builder_param,
    crypto::Key<kMasterPrfKeySize>&&        master_key,
    std::array<uint8_t, kEncryptionKeySize> encryption_key)
    : tethys_store_builder(tethys_builder_param),
      cuckoo_builder(cuckoo_builder_param), master_prf(std::move(master_key)),
      tethys_encryption_encoder(encryption_key)
{
}


template<class Params>
void PlutoBuilder<Params>::build()
{
    logger::logger()->info("Start building Pluto");

    logger::logger()->info("Commiting the cuckoo table");

    cuckoo_builder.commit();

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

    std::vector<size_t> block;
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
            typename Params::cuckoo_value_type v = {0x00};
            std::copy(block.begin(), block.end(), v.begin());

            // insert the list
            cuckoo_builder.insert(key, v);

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
                  const std::string kw, const std::list<unsigned> docs) {
                  this->insert_list(
                      kw, std::list<index_type>(docs.begin(), docs.end()));
                  kw_counter++;
                  size_t size = docs.size();

                  //   if (size > 512) {
                  //   logger::logger()->info(
                  //   "Large list. Keyword: {}, {} matches", kw, size);
                  //   }
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