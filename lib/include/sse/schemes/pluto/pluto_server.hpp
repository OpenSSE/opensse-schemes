#pragma once

#include <sse/schemes/pluto/types.hpp>
#include <sse/schemes/tethys/details/tethys_utils.hpp>
#include <sse/schemes/tethys/tethys_store.hpp>
#include <sse/schemes/tethys/types.hpp>

#include <array>

namespace sse {
namespace pluto {


template<class Params>
class PlutoServer
{
public:
    using tethys_store_type
        = tethys::TethysStore<Params::kPageSize,
                              tethys::tethys_core_key_type,
                              index_type,
                              typename Params::tethys_hasher_type>;


    using ht_type       = typename Params::ht_type;
    using ht_param_type = typename ht_type::param_type;

    static constexpr size_t kMasterPrfKeySize = tethys::kMasterPrfKeySize;

    PlutoServer(const std::string& tethys_path, const ht_param_type& ht_param);


    SearchResponse<Params::kPageSize> search(
        const SearchRequest& search_request);


private:
    tethys_store_type tethys_store;
    ht_type           hash_table;
};


template<class Params>
PlutoServer<Params>::PlutoServer(const std::string&   tethys_path,
                                 const ht_param_type& ht_param)
    : tethys_store(tethys_path, ""), hash_table(ht_param)
{
}

template<class Params>
auto PlutoServer<Params>::search(const SearchRequest& search_request)
    -> SearchResponse<Params::kPageSize>
{
    SearchResponse<Params::kPageSize> res;

    for (uint32_t i = 1;; i++) { // the first key for the hash table has index 1
        tethys::tethys_core_key_type key
            = tethys::details::derive_core_key(search_request.search_token, i);

        try {
            typename Params::ht_value_type v = hash_table.get(key);

            res.complete_lists.reserve(res.complete_lists.size() + v.size());
            res.complete_lists.insert(
                res.complete_lists.end(), v.begin(), v.end());
        } catch (const std::out_of_range& e) {
            break;
        }
    }

    // get the bucket pair from the Tethys store
    tethys::tethys_core_key_type key
        = tethys::details::derive_core_key(search_request.search_token, 0);
    res.tethys_bucket_pair = {key, tethys_store.get_buckets(key)};

    return res;
}
} // namespace pluto
} // namespace sse