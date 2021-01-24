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

#include <sse/schemes/utils/logger.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <rocksdb/db.h>
#include <rocksdb/memtablerep.h>
#include <rocksdb/options.h>
#include <rocksdb/table.h>

#include <iostream>
#include <list>
#include <memory>

namespace sse {
namespace sophos {

class RockDBWrapper
{
public:
    RockDBWrapper() = delete;
    inline explicit RockDBWrapper(const std::string& path);
    inline ~RockDBWrapper();

    inline bool get(const std::string& key, std::string& data) const;
    template<size_t N, typename V>
    inline bool get(const std::array<uint8_t, N>& key, V& data) const;

    template<typename V>
    inline bool get(const uint8_t* key,
                    const uint8_t  key_length,
                    V&             data) const;

    template<size_t N, typename V>
    inline bool put(const std::array<uint8_t, N>& key, const V& data);

    template<size_t N>
    inline bool remove(const std::array<uint8_t, N>& key);

    inline bool remove(const uint8_t* key, const uint8_t key_length);

    inline void flush(bool blocking = true);

    inline uint64_t approximate_size() const;

private:
    rocksdb::DB* db_;
};

RockDBWrapper::RockDBWrapper(const std::string& path) : db_(nullptr)
{
    rocksdb::Options options;
    options.create_if_missing = true;


    rocksdb::CuckooTableOptions cuckoo_options;
    cuckoo_options.identity_as_first_hash = false;
    cuckoo_options.hash_table_ratio       = 0.9;


    //        cuckoo_options.use_module_hash = false;
    //        cuckoo_options.identity_as_first_hash = true;

    options.table_cache_numshardbits = 4;
    options.max_open_files           = -1;


    options.table_factory.reset(rocksdb::NewCuckooTableFactory(cuckoo_options));

    options.memtable_factory = std::make_shared<rocksdb::VectorRepFactory>();

    options.compression            = rocksdb::kNoCompression;
    options.bottommost_compression = rocksdb::kDisableCompressionOption;

    options.compaction_style = rocksdb::kCompactionStyleLevel;
    options.info_log_level   = rocksdb::InfoLogLevel::INFO_LEVEL;


    //        options.max_grandparent_overlap_factor = 10;

    options.delayed_write_rate         = 8388608;
    options.max_background_compactions = 20;

    //        options.disableDataSync = true;
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

RockDBWrapper::~RockDBWrapper()
{
    delete db_;
}

bool RockDBWrapper::get(const std::string& key, std::string& data) const
{
    rocksdb::Status s = db_->Get(rocksdb::ReadOptions(), key, &data);

    return s.ok();
}

template<size_t N, typename V>
bool RockDBWrapper::get(const std::array<uint8_t, N>& key, V& data) const
{
    rocksdb::Slice k_s(reinterpret_cast<const char*>(key.data()), N);
    std::string    value;

    rocksdb::Status s
        = db_->Get(rocksdb::ReadOptions(false, true), k_s, &value);

    if (s.ok()) {
        ::memcpy(&data, value.data(), sizeof(V));
    }

    return s.ok();
}

template<typename V>
bool RockDBWrapper::get(const uint8_t* key,
                        const uint8_t  key_length,
                        V&             data) const
{
    rocksdb::Slice k_s(reinterpret_cast<const char*>(key), key_length);
    std::string    value;

    rocksdb::Status s
        = db_->Get(rocksdb::ReadOptions(false, true), k_s, &value);

    if (s.ok()) {
        ::memcpy(&data, value.data(), sizeof(V));
    }

    return s.ok();
}


template<size_t N, typename V>
bool RockDBWrapper::put(const std::array<uint8_t, N>& key, const V& data)
{
    rocksdb::Slice k_s(reinterpret_cast<const char*>(key.data()), N);
    rocksdb::Slice k_v(reinterpret_cast<const char*>(&data), sizeof(V));

    rocksdb::Status s = db_->Put(rocksdb::WriteOptions(), k_s, k_v);

    /* LCOV_EXCL_START */
    if (!s.ok()) {
        logger::logger()->error(
            std::string("Unable to insert pair in the database\nkey=")
            + utility::hex_string(key) + "\ndata=" + utility::hex_string(data)
            + "\nRocksdb status: " + s.ToString());
    }
    /* LCOV_EXCL_STOP */

    return s.ok();
}

template<size_t N>
bool RockDBWrapper::remove(const std::array<uint8_t, N>& key)
{
    rocksdb::Slice k_s(reinterpret_cast<const char*>(key.data()), N);

    rocksdb::Status s = db_->Delete(rocksdb::WriteOptions(), k_s);

    return s.ok();
}

bool RockDBWrapper::remove(const uint8_t* key, const uint8_t key_length)
{
    rocksdb::Slice k_s(reinterpret_cast<const char*>(key), key_length);

    rocksdb::Status s = db_->Delete(rocksdb::WriteOptions(), k_s);

    return s.ok();
}

void RockDBWrapper::flush(bool blocking)
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

uint64_t RockDBWrapper::approximate_size() const
{
    uint64_t v;
    bool     flag
        = db_->GetIntProperty(rocksdb::DB::Properties::kEstimateNumKeys, &v);
    (void)flag;

    assert(flag);

    return v;
}


class RocksDBCounter
{
public:
    RocksDBCounter() = delete;
    explicit RocksDBCounter(const std::string& path);
    inline ~RocksDBCounter()
    {
        delete db_;
    };

    bool get(const std::string& key, uint32_t& val) const;

    bool get_and_increment(const std::string& key, uint32_t& val);

    bool increment(const std::string& key, uint32_t default_value = 0);

    bool set(const std::string& key, uint32_t val);

    bool remove_key(const std::string& key);

    void flush(bool blocking = true);

    inline uint64_t approximate_size() const
    {
        uint64_t v = 0;
        db_->GetIntProperty(rocksdb::DB::Properties::kEstimateNumKeys, &v);

        return v;
    }

private:
    rocksdb::DB* db_;
};


template<class T>
struct serialization
{
    std::string serialize(const T&);
    bool        deserialize(std::string::iterator&       begin,
                            const std::string::iterator& end,
                            T&                           out);
};

template<typename T, class Serializer = serialization<T>>
class RockDBListStore
{
public:
    using serializer = Serializer;

    RockDBListStore() = delete;
    inline explicit RockDBListStore(const std::string& path);
    inline ~RockDBListStore();

    // find the list associated to key and append elements to data
    bool get(const std::string& key,
             std::list<T>&      data,
             serializer&        deser) const;
    bool get(const std::string& key, std::list<T>& data) const
    {
        serializer deser = serializer();
        return get(key, data, deser);
    }

    template<size_t N>
    inline bool get(const std::array<uint8_t, N>& key,
                    std::list<T>&                 data,
                    serializer&                   deser) const
    {
        return get(key.data(), N, data, deser);
    }
    template<size_t N>
    inline bool get(const std::array<uint8_t, N>& key, std::list<T>& data) const
    {
        serializer deser = serializer();
        return get(key, data, deser);
    }

    bool        get(const uint8_t* key,
                    const uint8_t  key_length,
                    std::list<T>&  data,
                    serializer&    deser) const;
    inline bool get(const uint8_t* key,
                    const uint8_t  key_length,
                    std::list<T>&  data) const
    {
        serializer deser = serializer();
        return get(key, key_length, data, deser);
    }


    template<size_t N>
    bool put(const std::array<uint8_t, N>& key,
             const std::list<T>&           data,
             serializer&                   ser);

    template<size_t N>
    inline bool put(const std::array<uint8_t, N>& key, const std::list<T>& data)
    {
        serializer ser = serializer();
        return put<N>(key, data, ser);
    }


    void flush(bool blocking = true);

private:
    rocksdb::DB* db_;
};

template<typename T, class Serializer>
// cppcheck (on Xenial) can be annoying with lineskips
// cppcheck-suppress uninitMemberVar
RockDBListStore<T, Serializer>::RockDBListStore(const std::string& path)
    : db_(nullptr)
{
    rocksdb::Options options;
    options.create_if_missing = true;


    rocksdb::CuckooTableOptions cuckoo_options;
    cuckoo_options.identity_as_first_hash = false;
    cuckoo_options.hash_table_ratio       = 0.9;

    options.table_cache_numshardbits = 4;
    options.max_open_files           = -1;

    options.compression            = rocksdb::kNoCompression;
    options.bottommost_compression = rocksdb::kDisableCompressionOption;

    options.compaction_style = rocksdb::kCompactionStyleLevel;
    options.info_log_level   = rocksdb::InfoLogLevel::INFO_LEVEL;

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

template<typename T, class Serializer>
RockDBListStore<T, Serializer>::~RockDBListStore()
{
    delete db_;
}

template<typename T, class Serializer>
bool RockDBListStore<T, Serializer>::get(const std::string& key,
                                         std::list<T>&      data,
                                         serializer&        deser) const
{
    // empty the list first
    data.clear();

    std::string     raw_string;
    rocksdb::Status s = db_->Get(rocksdb::ReadOptions(), key, &raw_string);

    if (s.ok()) {
        auto       it  = raw_string.begin();
        const auto end = raw_string.end();
        T          elt;

        while (deser.deserialize(it, end, elt)) {
            data.emplace_back(std::move(elt));
        }
    }
    return s.ok();
}

template<typename T, class Serializer>
bool RockDBListStore<T, Serializer>::get(const uint8_t* key,
                                         const uint8_t  key_length,
                                         std::list<T>&  data,
                                         serializer&    deser) const
{
    rocksdb::Slice k_s(reinterpret_cast<const char*>(key), key_length);
    std::string    raw_string;

    // empty the list first
    data.clear();

    rocksdb::Status s
        = db_->Get(rocksdb::ReadOptions(false, true), k_s, &raw_string);

    if (s.ok()) {
        auto       it  = raw_string.begin();
        const auto end = raw_string.end();
        T          elt;

        while (deser.deserialize(it, end, elt)) {
            //                data.push_back(std::move<T>(elt));
            data.push_back(elt);
        }
    }
    return s.ok();
}

template<typename T, class Serializer>
// cppcheck-suppress syntaxError
template<size_t N>
bool RockDBListStore<T, Serializer>::put(const std::array<uint8_t, N>& key,
                                         const std::list<T>&           data,
                                         serializer&                   ser)
{
    std::string serialized_list;

    for (T elt : data) {
        serialized_list += ser.serialize(elt);
    }

    rocksdb::Slice k_s(reinterpret_cast<const char*>(key.data()), N);
    //        rocksdb::Slice k_v(reinterpret_cast<const
    //        char*>(&serialized_list.data()), sizeof(V));
    rocksdb::Slice k_v(serialized_list.data(), serialized_list.size());

    rocksdb::Status s = db_->Put(rocksdb::WriteOptions(), k_s, k_v);

    /* LCOV_EXCL_START */
    if (!s.ok()) {
        logger::logger()->error(
            std::string("Unable to insert pair in the database\nkey=")
            + utility::hex_string(key)
            + "\ndata=" + utility::hex_string(serialized_list)
            + "\nRocksdb status: " + s.ToString());
    }
    /* LCOV_EXCL_STOP */

    return s.ok();
}


template<typename T, class Serializer>
void RockDBListStore<T, Serializer>::flush(bool blocking)
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
