#pragma once

#include <sse/schemes/pluto/types.hpp>
#include <sse/schemes/utils/logger.hpp>

#include <rocksdb/db.h>
#include <rocksdb/memtablerep.h>
#include <rocksdb/options.h>
#include <rocksdb/table.h>

#include <memory>

namespace sse {
namespace pluto {

struct GenericRocksDBStoreParams
{
    std::string      path;
    rocksdb::Options rocksdb_options;

    static rocksdb::Options make_rocksdb_cuckoo_options();
    static rocksdb::Options make_rocksdb_regular_table_options();
};

class GenericRocksDBStore
{
public:
    explicit GenericRocksDBStore(const GenericRocksDBStoreParams& params);

    void commit();

    template<size_t N>
    void insert(const tethys::tethys_core_key_type& key,
                const std::array<index_type, N>&    value);

    template<size_t N>
    std::array<index_type, N> get(const tethys::tethys_core_key_type& key);

private:
    std::unique_ptr<rocksdb::DB> db;
};

template<size_t N>
void GenericRocksDBStore::insert(const tethys::tethys_core_key_type& key,
                                 const std::array<index_type, N>&    value)
{
    rocksdb::Slice k_s(reinterpret_cast<const char*>(key.data()),
                       tethys::kTethysCoreKeySize);
    rocksdb::Slice k_v(reinterpret_cast<const char*>(&value),
                       sizeof(index_type) * N);

    rocksdb::Status s = db->Put(rocksdb::WriteOptions(), k_s, k_v);

    /* LCOV_EXCL_START */
    if (!s.ok()) {
        logger::logger()->error(
            std::string("Unable to insert pair in the database\nkey=")
            + utility::hex_string(key) + "\ndata=" + utility::hex_string(value)
            + "\nRocksdb status: " + s.ToString());
        throw std::exception();
    }
    /* LCOV_EXCL_STOP */
}

template<size_t N>
std::array<index_type, N> GenericRocksDBStore::get(
    const tethys::tethys_core_key_type& key)
{
    rocksdb::Slice k_s(reinterpret_cast<const char*>(key.data()),
                       tethys::kTethysCoreKeySize);

    std::string     value;
    rocksdb::Status s = db->Get(rocksdb::ReadOptions(false, true), k_s, &value);

    std::array<index_type, N> content;

    if (s.ok()) {
        ::memcpy(content.data(), value.data(), N * sizeof(index_type));
    } else {
        throw std::out_of_range("Key not found");
    }

    return content;
}


template<size_t N>
class RocksDBStoreBuilder
{
public:
    using param_type = GenericRocksDBStoreParams;
    explicit RocksDBStoreBuilder(const param_type& params) : store(params)
    {
    }

    void commit()
    {
        store.commit();
    }
    void insert(const tethys::tethys_core_key_type& key,
                const std::array<index_type, N>&    value)
    {
        store.insert(key, value);
    }

    std::array<index_type, N> get(const tethys::tethys_core_key_type& key)
    {
        return store.get<N>(key);
    }

private:
    GenericRocksDBStore store;
};


template<size_t PAGE_SIZE>
struct RocksDBPlutoParams
{
    static constexpr size_t kPageSize = PAGE_SIZE;

    using tethys_inner_encoder_type
        = tethys::encoders::EncodeSeparateEncoder<tethys::tethys_core_key_type,
                                                  index_type,
                                                  kPageSize>;

    using tethys_encoder_type
        = tethys::encoders::EncryptEncoder<tethys_inner_encoder_type,
                                           kPageSize>;

    static constexpr size_t kTethysMaxListLength
        = PAGE_SIZE / sizeof(index_type)
          - tethys_encoder_type::kListControlValues;

    using tethys_stash_encoder_type = tethys_inner_encoder_type;

    using tethys_hasher_type = tethys::IdentityHasher;

    static constexpr size_t kPlutoListLength = kTethysMaxListLength;

    using ht_value_type   = std::array<index_type, kPlutoListLength>;
    using ht_builder_type = RocksDBStoreBuilder<kPlutoListLength>;

    using ht_type = RocksDBStoreBuilder<kPlutoListLength>;
};

} // namespace pluto
} // namespace sse