#pragma once


#include <sse/schemes/tethys/details/tethys_utils.hpp>
#include <sse/schemes/tethys/tethys_store_builder.hpp>
#include <sse/schemes/tethys/types.hpp>
#include <sse/schemes/utils/rocksdb_wrapper.hpp>

#include <sse/crypto/key.hpp>
#include <sse/crypto/prf.hpp>

#include <array>
#include <list>

namespace sse {
namespace tethys {


template<class StoreBuilder>
class TethysBuilder
{
public:
    using builder_type       = StoreBuilder;
    using value_encoder_type = typename builder_type::value_encoder_type;
    using stash_encoder_type = typename builder_type::stash_encoder_type;

    TethysBuilder(const TethysStoreBuilderParam&   params,
                  const std::string&               counter_db_path,
                  crypto::Key<kMasterPrfKeySize>&& master_key);


    void insert_list(const std::string& keyword, std::list<uint64_t> indexes);

    void build();
    void build(value_encoder_type& encoder, stash_encoder_type& stash_encoder);

private:
    StoreBuilder           store_builder;
    sophos::RocksDBCounter counter_db;
    master_prf_type        master_prf;
};

template<class StoreBuilder>
TethysBuilder<StoreBuilder>::TethysBuilder(
    const TethysStoreBuilderParam&   builder_params,
    const std::string&               counter_db_path,
    crypto::Key<kMasterPrfKeySize>&& master_key)
    : store_builder(builder_params), counter_db(counter_db_path),
      master_prf(std::move(master_key))
{
}

template<class StoreBuilder>
void TethysBuilder<StoreBuilder>::build()
{
    store_builder.build();
    counter_db.flush(true);
}

template<class StoreBuilder>
void TethysBuilder<StoreBuilder>::build(value_encoder_type& encoder,
                                        stash_encoder_type& stash_encoder)
{
    store_builder.build(encoder, stash_encoder);
    counter_db.flush(true);
}


template<class StoreBuilder>
void TethysBuilder<StoreBuilder>::insert_list(const std::string&  keyword,
                                              std::list<uint64_t> indexes)
{
    size_t counter       = 0;
    size_t block_counter = 0;

    std::vector<size_t> block;
    block.reserve(StoreBuilder::kBucketSize);

    std::array<uint8_t, kSearchTokenSize> keyword_token
        = master_prf.prf(keyword);

    for (uint64_t id : indexes) {
        counter++;
        block.push_back(id);

        if (block.size() == StoreBuilder::kBucketSize) {
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
    typename StoreBuilder::key_type key;
    // generate the key

    // insert the list
    store_builder.insert_list(key, block);

    // add the counter to the counter db
    counter_db.set(keyword, counter);
}

} // namespace tethys
} // namespace sse