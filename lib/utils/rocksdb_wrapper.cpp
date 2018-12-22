//
// Sophos - Forward Private Searchable Encryption
// Copyright (C) 2016 Raphael Bost
//
// This file is part of Sophos.
//
// Sophos is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// Sophos is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Sophos.  If not, see <http://www.gnu.org/licenses/>.
//

#include <sse/schemes/utils/rocksdb_wrapper.hpp>

namespace sse {
namespace sophos {


RocksDBCounter::RocksDBCounter(const std::string& path) : db_(nullptr)
{
    rocksdb::Options options;
    options.create_if_missing = true;


    rocksdb::CuckooTableOptions cuckoo_options;
    cuckoo_options.identity_as_first_hash = false;
    cuckoo_options.hash_table_ratio       = 0.9;

    options.table_cache_numshardbits = 4;
    options.max_open_files           = -1;


    //            options.table_factory.reset(rocksdb::NewCuckooTableFactory(cuckoo_options));

    options.compression            = rocksdb::kNoCompression;
    options.bottommost_compression = rocksdb::kDisableCompressionOption;

    options.compaction_style = rocksdb::kCompactionStyleLevel;
    options.info_log_level   = rocksdb::InfoLogLevel::INFO_LEVEL;


    //        options.max_grandparent_overlap_factor = 10;

    options.delayed_write_rate         = 8388608;
    options.max_background_compactions = 20;

    options.allow_mmap_reads                       = true;
    options.new_table_reader_for_compaction_inputs = true;

    options.allow_concurrent_memtable_write
        = options.memtable_factory->IsInsertConcurrentlySupported();

    options.max_bytes_for_level_base            = 4294967296; // 4 GB
    options.arena_block_size                    = 134217728;  // 128 MB
    options.level0_file_num_compaction_trigger  = 10;
    options.level0_slowdown_writes_trigger      = 16;
    options.hard_pending_compaction_bytes_limit = 137438953472; // 128 GB
    options.target_file_size_base               = 201327616;
    options.write_buffer_size                   = 1073741824; // 1GB

    //        options.optimize_filters_for_hits = true;


    rocksdb::Status status = rocksdb::DB::Open(options, path, &db_);
    /* LCOV_EXCL_START */
    if (!status.ok()) {
        logger::logger()->critical("Unable to open the database:\n "
                                   + status.ToString());
        db_ = nullptr;

        throw std::runtime_error("Unable to open the database located at "
                                 + path);
    }
    /* LCOV_EXCL_STOP */
}

bool RocksDBCounter::get(const std::string& key, uint32_t& val) const
{
    std::string data;

    rocksdb::Status s = db_->Get(rocksdb::ReadOptions(), key, &data);

    logger::logger()->debug("Get: " + utility::hex_string(key)
                            + "\nStatus: " + s.ToString());

    if (s.ok()) {
        ::memcpy(&val, data.data(), sizeof(uint32_t));
    }

    return s.ok();
}

bool RocksDBCounter::get_and_increment(const std::string& key, uint32_t& val)
{
    std::string data;

    rocksdb::Status s = db_->Get(rocksdb::ReadOptions(), key, &data);

    logger::logger()->debug("Get and increment: " + utility::hex_string(key)
                            + "\nStatus: " + s.ToString());

    if (s.ok()) {
        ::memcpy(&val, data.data(), sizeof(uint32_t));

        val++;
    } else {
        val = 0;
    }

    rocksdb::Slice k_v(reinterpret_cast<const char*>(&val), sizeof(uint32_t));

    s = db_->Put(rocksdb::WriteOptions(), key, k_v);

    /* LCOV_EXCL_START */
    if (!s.ok()) {
        logger::logger()->error("Unable to insert pair in the database\nkey="
                                + utility::hex_string(key)
                                + "\nvalue=" + std::to_string(val)
                                + "\nRocksdb status: " + s.ToString());
    }
    /* LCOV_EXCL_STOP */

    return s.ok();
}

bool RocksDBCounter::increment(const std::string& key, uint32_t default_value)
{
    std::string data;
    uint32_t    val;

    rocksdb::Status s = db_->Get(rocksdb::ReadOptions(), key, &data);

    if (s.ok()) {
        // the key has been found
        ::memcpy(&val, data.data(), sizeof(uint32_t));

        val++;
    } else {
        val = default_value;
    }

    rocksdb::Slice k_v(reinterpret_cast<const char*>(&val), sizeof(uint32_t));

    s = db_->Put(rocksdb::WriteOptions(), key, k_v);

    /* LCOV_EXCL_START */
    if (!s.ok()) {
        logger::logger()->error(
            "Unable to increment value in the database\nkey="
            + utility::hex_string(key) + "\nvalue=" + std::to_string(val)
            + "\nRocksdb status: " + s.ToString());
    }
    /* LCOV_EXCL_STOP */

    return s.ok();
}

bool RocksDBCounter::set(const std::string& key, uint32_t val)
{
    rocksdb::Slice k_v(reinterpret_cast<const char*>(&val), sizeof(uint32_t));

    rocksdb::Status s = db_->Put(rocksdb::WriteOptions(), key, k_v);

    /* LCOV_EXCL_START */
    if (!s.ok()) {
        logger::logger()->error(
            std::string("Unable to insert pair in the counter database\nkey=")
            + utility::hex_string(key) + "\nvalue=" + std::to_string(val)
            + "\nRocksdb status: " + s.ToString());
    }
    /* LCOV_EXCL_STOP */

    return s.ok();
}


bool RocksDBCounter::remove_key(const std::string& key)
{
    rocksdb::Status s = db_->Delete(rocksdb::WriteOptions(), key);

    return s.ok();
}

void RocksDBCounter::flush(bool blocking)
{
    rocksdb::FlushOptions options;

    options.wait = blocking;

    rocksdb::Status s = db_->Flush(options);

    /* LCOV_EXCL_START */
    if (!s.ok()) {
        logger::logger()->error("DB Flush failed: " + s.ToString());
    }
    /* LCOV_EXCL_STOP */
}
} // namespace sophos
} // namespace sse
