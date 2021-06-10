#pragma once


#include <sse/schemes/tethys/details/tethys_utils.hpp>
#include <sse/schemes/tethys/encoders/encode_encrypt.hpp>
#include <sse/schemes/tethys/tethys_store_builder.hpp>
#include <sse/schemes/tethys/types.hpp>
#include <sse/schemes/utils/logger.hpp>
#include <sse/schemes/utils/rocksdb_wrapper.hpp>

#include <sse/crypto/key.hpp>
#include <sse/crypto/prf.hpp>
#include <sse/dbparser/json/DBParserJSON.h>

#include <array>
#include <list>

namespace sse {
namespace tethys {

namespace details {
template<class StoreBuilder>
class GenericTethysBuilder
{
public:
    using builder_type       = StoreBuilder;
    using value_encoder_type = typename builder_type::value_encoder_type;
    using stash_encoder_type = typename builder_type::stash_encoder_type;

    static_assert(
        std::is_same<index_type, typename StoreBuilder::value_type>::value,
        "Store value type must be index_type");

    GenericTethysBuilder(const TethysStoreBuilderParam&   params,
                         const std::string&               counter_db_path,
                         crypto::Key<kMasterPrfKeySize>&& master_key);


    void insert_list(const std::string&         keyword,
                     const std::list<uint64_t>& indexes);

    void build();
    void build(value_encoder_type& encoder, stash_encoder_type& stash_encoder);

private:
    StoreBuilder           store_builder;
    sophos::RocksDBCounter counter_db;
    master_prf_type        master_prf;
};

template<class StoreBuilder>
GenericTethysBuilder<StoreBuilder>::GenericTethysBuilder(
    const TethysStoreBuilderParam&   builder_params,
    const std::string&               counter_db_path,
    crypto::Key<kMasterPrfKeySize>&& master_key)
    : store_builder(builder_params), counter_db(counter_db_path),
      master_prf(std::move(master_key))
{
}

template<class StoreBuilder>
void GenericTethysBuilder<StoreBuilder>::build()
{
    store_builder.build();
    counter_db.flush(true);
}

template<class StoreBuilder>
void GenericTethysBuilder<StoreBuilder>::build(
    value_encoder_type& encoder,
    stash_encoder_type& stash_encoder)
{
    store_builder.build(encoder, stash_encoder);
    counter_db.flush(true);
}


template<class StoreBuilder>
void GenericTethysBuilder<StoreBuilder>::insert_list(
    const std::string&         keyword,
    const std::list<uint64_t>& indexes)
{
    size_t counter       = 0;
    size_t block_counter = 0;

    std::vector<uint64_t> block;
    block.reserve(StoreBuilder::kBucketSize);

    std::array<uint8_t, kSearchTokenSize> keyword_token
        = master_prf.prf(keyword);

    for (uint64_t id : indexes) {
        counter++;
        block.push_back(id);

        if (block.size() == StoreBuilder::kMaxListSize) {
            // generate the core key
            tethys_core_key_type key
                = details::derive_core_key(keyword_token, block_counter);

            // insert the list
            store_builder.insert_list(key, block);

            block_counter++;
            block.clear();
            block.reserve(
                StoreBuilder::kBucketSize); // clear() does not guaranty the
                                            // capacity to stay the same
        }
    }

    // take care of the incomplete block
    // generate the key
    tethys_core_key_type key
        = details::derive_core_key(keyword_token, block_counter);


    // insert the list
    store_builder.insert_list(key, block);

    // add the block counter to the counter db
    // this represents the number of blocks in the db (hence the +1)
    // counter_db.set(keyword, counter);
    counter_db.set(keyword, block_counter + 1);
}
} // namespace details


template<size_t PAGE_SIZE,
         class ValueEncoder,
         class StashEncoder = ValueEncoder,
         class TethysHasher = IdentityHasher>
class TethysBuilder
{
public:
    static constexpr size_t kPageSize = PAGE_SIZE;

    using inner_encoder_type = ValueEncoder;
    using encrypt_encoder_type
        = encoders::EncryptEncoder<inner_encoder_type, kPageSize>;
    using stash_encoder_type = StashEncoder;

    using tethys_store_type = TethysStoreBuilder<kPageSize,
                                                 tethys_core_key_type,
                                                 index_type,
                                                 TethysHasher,
                                                 encrypt_encoder_type,
                                                 stash_encoder_type>;
    ;

    static constexpr size_t kEncryptionKeySize = encrypt_encoder_type::kKeySize;

    TethysBuilder(const TethysStoreBuilderParam&          params,
                  const std::string&                      counter_db_path,
                  crypto::Key<kMasterPrfKeySize>&&        master_key,
                  std::array<uint8_t, kEncryptionKeySize> encryption_key);

    void insert_list(const std::string&         keyword,
                     const std::list<uint64_t>& indexes);

    bool load_inverted_index(const std::string& path);

    void build();

private:
    details::GenericTethysBuilder<tethys_store_type> generic_builder;
    encrypt_encoder_type                             encryption_encoder;
};

template<size_t PAGE_SIZE,
         class ValueEncoder,
         class StashEncoder,
         class TethysHasher>
TethysBuilder<PAGE_SIZE, ValueEncoder, StashEncoder, TethysHasher>::
    TethysBuilder(const TethysStoreBuilderParam&          params,
                  const std::string&                      counter_db_path,
                  crypto::Key<kMasterPrfKeySize>&&        master_key,
                  std::array<uint8_t, kEncryptionKeySize> encryption_key)
    : generic_builder(params, counter_db_path, std::move(master_key)),
      encryption_encoder(encryption_key)
{
}

template<size_t PAGE_SIZE,
         class ValueEncoder,
         class StashEncoder,
         class TethysHasher>
void TethysBuilder<PAGE_SIZE, ValueEncoder, StashEncoder, TethysHasher>::
    insert_list(const std::string& keyword, const std::list<uint64_t>& indexes)
{
    generic_builder.insert_list(keyword, indexes);
}

template<size_t PAGE_SIZE,
         class ValueEncoder,
         class StashEncoder,
         class TethysHasher>
void TethysBuilder<PAGE_SIZE, ValueEncoder, StashEncoder, TethysHasher>::build()
{
    stash_encoder_type stash_encoder;
    generic_builder.build(encryption_encoder, stash_encoder);
}


template<size_t PAGE_SIZE,
         class ValueEncoder,
         class StashEncoder,
         class TethysHasher>
bool TethysBuilder<PAGE_SIZE, ValueEncoder, StashEncoder, TethysHasher>::
    load_inverted_index(const std::string& path)
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

                  //   if (size > 512) {
                  //   logger::logger()->info(
                  //   "Large list. Keyword: {}, {} matches", kw, size);
                  //   }
                  entries_counter += size;

                  if ((kw_counter % 1000) == 0) {
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

        return true;
    } catch (std::exception& e) {
        logger::logger()->error("Failed to load file " + path + ": "
                                + e.what());
        return false;
    }
    return false;
}

} // namespace tethys
} // namespace sse