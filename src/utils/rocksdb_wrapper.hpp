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

#pragma once

#include "logger.hpp"
#include "utils.hpp"

#include <rocksdb/db.h>
#include <rocksdb/table.h>
#include <rocksdb/memtablerep.h>
#include <rocksdb/options.h>

#include <iostream>

namespace sse {
namespace sophos {

class RockDBWrapper {
public:
    RockDBWrapper() = delete;
    inline RockDBWrapper(const std::string &path);
    inline ~RockDBWrapper();
    
    inline bool get(const std::string &key, std::string &data) const;
    template <size_t N, typename V>
        inline bool get(const std::array<uint8_t, N> &key, V &data) const;
    
    template <typename V>
    inline bool get(const uint8_t *key, const uint8_t key_length, V &data) const;

    template <size_t N, typename V>
    inline bool put(const std::array<uint8_t, N> &key, const V &data);

    inline void flush(bool blocking = true);
private:
    rocksdb::DB* db_;
    
};

    RockDBWrapper::RockDBWrapper(const std::string &path)
    : db_(NULL)
    {
        rocksdb::Options options;
        options.create_if_missing = true;
        
        
        rocksdb::CuckooTableOptions cuckoo_options;
        cuckoo_options.identity_as_first_hash = false;
        cuckoo_options.hash_table_ratio = 0.9;

        
//        cuckoo_options.use_module_hash = false;
//        cuckoo_options.identity_as_first_hash = true;

        options.table_cache_numshardbits = 4;
        options.max_open_files = -1;
        
        
        
        
        options.table_factory.reset(rocksdb::NewCuckooTableFactory(cuckoo_options));
        
        options.memtable_factory.reset(new rocksdb::VectorRepFactory());
        
        options.compression = rocksdb::kNoCompression;
        options.bottommost_compression = rocksdb::kDisableCompressionOption;

        options.compaction_style = rocksdb::kCompactionStyleLevel;
        options.info_log_level = rocksdb::InfoLogLevel::INFO_LEVEL;


//        options.max_grandparent_overlap_factor = 10;
        
        options.delayed_write_rate = 8388608;
        options.max_background_compactions = 20;

//        options.disableDataSync = true;
        options.allow_mmap_reads = true;
        options.new_table_reader_for_compaction_inputs = true;
        
        options.allow_concurrent_memtable_write = false;
        
        options.max_bytes_for_level_base = 4294967296; // 4 GB
        options.arena_block_size = 134217728; // 128 MB
        options.level0_file_num_compaction_trigger = 10;
        options.level0_slowdown_writes_trigger = 16;
        options.hard_pending_compaction_bytes_limit = 137438953472; // 128 GB
        options.target_file_size_base=201327616;
        options.write_buffer_size=1073741824; // 1GB
        
//        options.optimize_filters_for_hits = true;
        
        
        rocksdb::Status status = rocksdb::DB::Open(options, path, &db_);
        
        if (!status.ok()) {
            logger::log(logger::CRITICAL) << "Unable to open the database: " << status.ToString() << std::endl;
            db_ = NULL;
        }
    }
    
    RockDBWrapper::~RockDBWrapper()
    {
        if (db_) {
            delete db_;
        }
    }

    bool RockDBWrapper::get(const std::string &key, std::string &data) const
    {
        rocksdb::Status s = db_->Get(rocksdb::ReadOptions(), key, &data);
        
        return s.ok();
    }
    
    template <size_t N, typename V>
    bool RockDBWrapper::get(const std::array<uint8_t, N> &key, V &data) const
    {
        rocksdb::Slice k_s(reinterpret_cast<const char*>( key.data() ),N);
        std::string value;
        
        rocksdb::Status s = db_->Get(rocksdb::ReadOptions(false,true), k_s, &value);
        
        if(s.ok()){
            ::memcpy(&data, value.data(), sizeof(V));
        }
        
        return s.ok();
    }
    
    template <typename V>
    bool RockDBWrapper::get(const uint8_t *key, const uint8_t key_length, V &data) const
    {
        rocksdb::Slice k_s(reinterpret_cast<const char*>( key ),key_length);
        std::string value;
        
        rocksdb::Status s = db_->Get(rocksdb::ReadOptions(false,true), k_s, &value);
        
        if(s.ok()){
            ::memcpy(&data, value.data(), sizeof(V));
        }
        
        return s.ok();
    }
    

    template <size_t N, typename V>
    bool RockDBWrapper::put(const std::array<uint8_t, N> &key, const V &data)
    {
        rocksdb::Slice k_s(reinterpret_cast<const char*>(key.data()),N);
        rocksdb::Slice k_v(reinterpret_cast<const char*>(&data), sizeof(V));

        rocksdb::Status s = db_->Put(rocksdb::WriteOptions(), k_s, k_v);
        
        if (!s.ok()) {
            logger::log(logger::ERROR) << "Unable to insert pair in the database: " << s.ToString() << std::endl;
            logger::log(logger::ERROR) << "Failed on pair: key=" << hex_string(key) << ", data=" << std::hex << data << std::endl;

        }
//        assert(s.ok());
        
        return s.ok();
    }

    
    void RockDBWrapper::flush(bool blocking)
    {
        rocksdb::FlushOptions options;
        
        options.wait = blocking;
        
        rocksdb::Status s = db_->Flush(options);
        
        if (!s.ok()) {
            logger::log(logger::ERROR) << "DB Flush failed: " << s.ToString() << std::endl;            
        }

    }

}
}
