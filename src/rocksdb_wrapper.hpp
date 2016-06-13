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
    
    template <size_t N, typename V>
    inline bool put(const std::array<uint8_t, N> &key, const V &data);

private:
    rocksdb::DB* db_;
    
};

    RockDBWrapper::RockDBWrapper(const std::string &path)
    : db_(NULL)
    {
        rocksdb::Options options;
        options.create_if_missing = true;
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
        
        rocksdb::Status s = db_->Get(rocksdb::ReadOptions(), db_->DefaultColumnFamily(), k_s, &value);
        
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

        rocksdb::Status s = db_->Put(rocksdb::WriteOptions(), db_->DefaultColumnFamily(), k_s, k_v);
        
        assert(s.ok());
        return s.ok();
    }

}
}