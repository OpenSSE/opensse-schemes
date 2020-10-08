#pragma once

#include <sse/schemes/oceanus/types.hpp>
#include <sse/schemes/tethys/encoders/encode_encrypt.hpp>
#include <sse/schemes/tethys/encoders/encode_separate.hpp>
#include <sse/schemes/tethys/types.hpp>

namespace sse {
namespace pluto {

using index_type = uint64_t;

template<size_t PAGE_SIZE>
struct DefaultPlutoParams
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

    static constexpr size_t kCuckooKeyOverhead
        = tethys::kTethysCoreKeySize / sizeof(index_type)
          + ((tethys::kTethysCoreKeySize % sizeof(index_type) == 0) ? 0 : 1);

    static_assert(kPageSize / sizeof(index_type) > kCuckooKeyOverhead,
                  "Cuckoo key too large");
    static constexpr size_t kCuckooListLength
        = kPageSize / sizeof(index_type) - kCuckooKeyOverhead;


    using cuckoo_value_type = std::array<index_type, kCuckooListLength>;

    static constexpr size_t kPlutoListLength
        = std::min(kCuckooListLength, kTethysMaxListLength);
};

struct PlutoKeySerializer
{
    static constexpr size_t serialization_length()
    {
        return tethys::kTethysCoreKeySize;
    }
    void serialize(const tethys::tethys_core_key_type& key, uint8_t* buffer)
    {
        memcpy(buffer, key.data(), tethys::kTethysCoreKeySize);
    }
};

template<class PlutoParams>
struct PlutoValueSerializer
{
    using value_type = typename PlutoParams::cuckoo_value_type;
    static constexpr size_t serialization_length()
    {
        return PlutoParams::kCuckooListLength * sizeof(index_type);
    }
    void serialize(const value_type& value, uint8_t* buffer)
    {
        assert(value.size() * sizeof(value_type::value_type)
               == serialization_length());
        memcpy(buffer, value.data(), value.size() * sizeof(index_type));
    }

    value_type deserialize(const uint8_t* buffer)
    {
        value_type res;
        memcpy(res.data(), buffer, res.size() * sizeof(index_type));

        return res;
    }
};
struct PlutoCuckooHasher
{
    oceanus::CuckooKey operator()(const tethys::tethys_core_key_type& key)
    {
        oceanus::CuckooKey ck;
        static_assert(sizeof(ck.h) == sizeof(tethys::tethys_core_key_type),
                      "Invalid source key size");

        memcpy(ck.h, key.data(), sizeof(ck.h));

        return ck;
    }
};
} // namespace pluto
} // namespace sse