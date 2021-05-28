#include "pluto/rocksdb_store.hpp"

namespace sse {
namespace pluto {

rocksdb::Options GenericRocksDBStoreParams::make_rocksdb_cuckoo_options()
{
    rocksdb::Options options;
    options.create_if_missing = true;


    rocksdb::CuckooTableOptions cuckoo_options;
    cuckoo_options.identity_as_first_hash = false;
    cuckoo_options.hash_table_ratio       = 0.9;


    options.table_cache_numshardbits = 4;
    options.max_open_files           = -1;


    options.table_factory.reset(rocksdb::NewCuckooTableFactory(cuckoo_options));

    options.memtable_factory = std::make_shared<rocksdb::VectorRepFactory>();

    options.compression            = rocksdb::kNoCompression;
    options.bottommost_compression = rocksdb::kDisableCompressionOption;

    options.compaction_style = rocksdb::kCompactionStyleLevel;
    options.info_log_level   = rocksdb::InfoLogLevel::INFO_LEVEL;

    // options.allow_mmap_reads                       = true;

    options.allow_concurrent_memtable_write
        = options.memtable_factory->IsInsertConcurrentlySupported();

    // options.max_bytes_for_level_base            = 4294967296; // 4 GB
    // options.arena_block_size                    = 134217728; // 128 MB
    // options.level0_file_num_compaction_trigger  = 10;
    // options.level0_slowdown_writes_trigger      = 16;
    // options.hard_pending_compaction_bytes_limit = 137438953472; // 128 GB
    // options.target_file_size_base = 256 * 1048576;
    // options.write_buffer_size                   = 1073741824; // 1GB

    return options;
}

rocksdb::Options GenericRocksDBStoreParams::make_rocksdb_regular_table_options()
{
    rocksdb::Options options;
    options.create_if_missing = true;


    options.table_cache_numshardbits = 4;
    options.max_open_files           = -1;

    options.compression            = rocksdb::kNoCompression;
    options.bottommost_compression = rocksdb::kDisableCompressionOption;

    options.compaction_style = rocksdb::kCompactionStyleLevel;
    options.info_log_level   = rocksdb::InfoLogLevel::INFO_LEVEL;

    // options.allow_mmap_reads = true;

    options.allow_concurrent_memtable_write
        = options.memtable_factory->IsInsertConcurrentlySupported();

    // options.max_bytes_for_level_base            = 4294967296; // 4 GB
    // options.arena_block_size                    = 134217728; // 128 MB
    // options.level0_file_num_compaction_trigger  = 10;
    // options.level0_slowdown_writes_trigger      = 16;
    // options.hard_pending_compaction_bytes_limit = 137438953472;  // 128 GB
    // options.target_file_size_base = 256 * 1048576; // 256 MB
    // options.write_buffer_size  = 1073741824; // 1GB

    return options;
}

GenericRocksDBStore::GenericRocksDBStore(
    const GenericRocksDBStoreParams& params)
    : db(nullptr)
{
    rocksdb::DB* db_ptr;

    rocksdb::Status status
        = rocksdb::DB::Open(params.rocksdb_options, params.path, &db_ptr);

    /* LCOV_EXCL_START */
    if (!status.ok()) {
        logger::logger()->critical("Unable to open the database:\n "
                                   + status.ToString());

        throw std::runtime_error("Unable to open the database located at "
                                 + params.path);
    }

    db.reset(db_ptr);

    /* LCOV_EXCL_STOP */
}

void GenericRocksDBStore::commit()
{
    rocksdb::FlushOptions options;

    options.wait = true;

    rocksdb::Status s = db->Flush(options);

    /* LCOV_EXCL_START */
    if (!s.ok()) {
        logger::logger()->error("DB Flush failed: " + s.ToString());
    }
    /* LCOV_EXCL_STOP */
}

} // namespace pluto
} // namespace sse
