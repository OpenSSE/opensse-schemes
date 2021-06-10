#include <sse/schemes/pluto/pluto_builder.hpp>
#include <sse/schemes/pluto/rocksdb_store.hpp>
#include <sse/schemes/tethys/tethys_store_builder.hpp>


namespace sse {
namespace pluto {
namespace test {
constexpr size_t kPageSize = 4096; // 4 kB

using default_param_type = DefaultPlutoParams<kPageSize>;
using rocksdb_param_type = RocksDBPlutoParams<kPageSize>;

constexpr size_t kTethysMaxListLength
    = default_param_type::kTethysMaxListLength;

using pluto_builder_type         = PlutoBuilder<default_param_type>;
using rocksdb_pluto_builder_type = PlutoBuilder<rocksdb_param_type>;


inline std::string cuckoo_table_path(const std::string& path)
{
    return path + "/cuckoo_table.bin";
}

inline std::string cuckoo_value_file_path(const std::string& path)
{
    return path + "/cuckoo_table.bin.tmp";
}


inline std::string rocksdb_path(const std::string& path)
{
    return path + "/full_blocks";
}

inline std::string tethys_table_path(const std::string& path)
{
    return path + "/tethys_table.bin";
}


inline std::string tethys_stash_path(const std::string& path)
{
    return path + "/tethys_stash.bin";
}

template<class Params>
typename Params::ht_builder_type::param_type make_pluto_ht_builder_params(
    const std::string& path,
    size_t             n_elts);

template<>
typename default_param_type::ht_builder_type::param_type
make_pluto_ht_builder_params<default_param_type>(const std::string& path,
                                                 size_t             n_elts)
{
    oceanus::CuckooBuilderParam cuckoo_builder_params;
    cuckoo_builder_params.value_file_path   = cuckoo_value_file_path(path);
    cuckoo_builder_params.cuckoo_table_path = cuckoo_table_path(path);

    cuckoo_builder_params.max_n_elements = (size_t)ceil(
        ((double)n_elts) / ((double)default_param_type::kPlutoListLength));
    cuckoo_builder_params.epsilon          = 0.3;
    cuckoo_builder_params.max_search_depth = 200;

    return cuckoo_builder_params;
}

template<>
typename rocksdb_param_type::ht_builder_type::param_type
make_pluto_ht_builder_params<rocksdb_param_type>(const std::string& path,
                                                 size_t             n_elts)
{
    (void)n_elts;
    GenericRocksDBStoreParams rocksdb_builder_params;
    rocksdb_builder_params.path = rocksdb_path(path);
    rocksdb_builder_params.rocksdb_options
        = GenericRocksDBStoreParams::make_rocksdb_regular_table_options();

    return rocksdb_builder_params;
}


template<class Params>
typename Params::ht_type::param_type make_pluto_ht_params(
    const std::string& path);


template<>
typename default_param_type::ht_type::param_type make_pluto_ht_params<
    default_param_type>(const std::string& path)
{
    return cuckoo_table_path(path);
}

template<>
typename rocksdb_param_type::ht_type::param_type make_pluto_ht_params<
    rocksdb_param_type>(const std::string& path)
{
    GenericRocksDBStoreParams rocksdb_builder_params;
    rocksdb_builder_params.path = rocksdb_path(path);
    rocksdb_builder_params.rocksdb_options
        = GenericRocksDBStoreParams::make_rocksdb_regular_table_options();

    return rocksdb_builder_params;
}


template<class Params>
PlutoBuilder<Params> create_pluto_builder(
    const std::string&      path,
    sse::crypto::Key<32>&&  derivation_key,
    std::array<uint8_t, 32> encryption_key,
    size_t                  n_elts)
{
    if (!sse::utility::create_directory(path, static_cast<mode_t>(0700))) {
        throw std::runtime_error(path + ": unable to create directory");
    }

    const size_t average_n_lists = 2 * (n_elts / kTethysMaxListLength + 1);

    const size_t expected_tot_n_elements
        = n_elts
          + default_param_type::tethys_encoder_type::kListControlValues
                * average_n_lists;

    tethys::TethysStoreBuilderParam tethys_builder_params;
    tethys_builder_params.max_n_elements    = expected_tot_n_elements;
    tethys_builder_params.tethys_table_path = tethys_table_path(path);
    tethys_builder_params.tethys_stash_path = tethys_stash_path(path);
    tethys_builder_params.epsilon           = 0.3;


    return PlutoBuilder<Params>(
        n_elts,
        tethys_builder_params,
        make_pluto_ht_builder_params<Params>(path, n_elts),
        std::move(derivation_key),
        encryption_key);
}


template<class Params>
PlutoBuilder<Params> create_load_pluto_builder(
    const std::string&      path,
    sse::crypto::Key<32>&&  derivation_key,
    std::array<uint8_t, 32> encryption_key,
    size_t                  n_elts,
    const std::string&      json_path)
{
    PlutoBuilder<Params> builder = create_pluto_builder<Params>(
        path, std::move(derivation_key), std::move(encryption_key), n_elts);

    builder.load_inverted_index(json_path);

    return builder;
}


} // namespace test
} // namespace pluto
} // namespace sse