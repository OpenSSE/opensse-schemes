#pragma once


#include <sse/schemes/tethys/tethys_store_builder.hpp>
#include <sse/schemes/tethys/types.hpp>

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
                  crypto::Key<kMasterPrfKeySize>&& master_key);


    void insert_list(const std::string& keyword, std::list<uint64_t> indexes);

    void build();
    void build(value_encoder_type& encoder, stash_encoder_type& stash_encoder);

private:
    StoreBuilder    store_builder;
    master_prf_type master_prf;
};

template<class StoreBuilder>
TethysBuilder<StoreBuilder>::TethysBuilder(
    const TethysStoreBuilderParam&   builder_params,
    crypto::Key<kMasterPrfKeySize>&& master_key)
    : store_builder(builder_params), master_prf(std::move(master_key))
{
}

template<class StoreBuilder>
void TethysBuilder<StoreBuilder>::build()
{
    store_builder.build();
}

template<class StoreBuilder>
void TethysBuilder<StoreBuilder>::build(value_encoder_type& encoder,
                                        stash_encoder_type& stash_encoder)
{
    store_builder.build(encoder, stash_encoder);
}

} // namespace tethys
} // namespace sse