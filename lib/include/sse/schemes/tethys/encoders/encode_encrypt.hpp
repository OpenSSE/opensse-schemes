#pragma once

#include <sse/schemes/tethys/core_types.hpp>

#include <sse/crypto/prf.hpp>

#include <cassert>
#include <cstring>
#include <sodium/crypto_stream_chacha20.h>
#include <sodium/utils.h>

#include <array>
#include <istream>
#include <ostream>

namespace sse {
namespace tethys {
namespace encoders {

template<class BaseEncoder, size_t BLOCK_SIZE>
class EncryptEncoder
{
public:
    static constexpr size_t kEncodedPayloadSize = BLOCK_SIZE;
    static constexpr size_t kListControlValues
        = BaseEncoder::kListControlValues;

    static constexpr size_t kBucketControlValues
        = BaseEncoder::kBucketControlValues;

    // static constexpr size_t kKeySize =
    // sse::crypto::Prf<BLOCK_SIZE>::kKeySize; using key_type =
    // sse::crypto::Key<kKeySize>;

    static constexpr size_t kKeySize = crypto_stream_chacha20_KEYBYTES;
    using key_type                   = std::array<uint8_t, kKeySize>;

    using keyword_type = typename BaseEncoder::key_type;
    using value_type   = typename BaseEncoder::value_type;

    explicit EncryptEncoder(key_type key)
        : encoder(),
          encryption_key(std::move(key)) /*, mask_prf(std::move(key))*/
    {
    }

    size_t start_block_encoding(uint8_t* buffer, size_t table_index)
    {
        return encoder.start_block_encoding(buffer, table_index);
    }

    size_t encode(uint8_t*                       buffer,
                  size_t                         table_index,
                  const keyword_type&            key,
                  const std::vector<value_type>& values,
                  TethysAssignmentInfo           infos)
    {
        return encoder.encode(buffer, table_index, key, values, infos);
    }

    size_t finish_block_encoding(uint8_t* buffer,
                                 size_t   table_index,
                                 size_t   written_bytes,
                                 size_t   remaining_bytes)
    {
        size_t offset = encoder.finish_block_encoding(
            buffer, table_index, written_bytes, remaining_bytes);

        (void)offset;

        assert(BLOCK_SIZE >= written_bytes + offset);

        // encrypt the block

        // NOLINTNEXTLINE(modernize-avoid-c-arrays)
        uint8_t nonce[crypto_stream_chacha20_NONCEBYTES];
        memset(nonce, 0x00, sizeof(nonce));
        memcpy(nonce, reinterpret_cast<uint8_t*>(&table_index), sizeof(size_t));

        crypto_stream_chacha20_xor(
            buffer, buffer, BLOCK_SIZE, nonce, encryption_key.data());

        // std::array<uint8_t, BLOCK_SIZE> mask = mask_prf.prf(
        //     reinterpret_cast<uint8_t*>(&table_index), sizeof(size_t));

        // for (size_t i = 0; i < BLOCK_SIZE; i++) {
        //     buffer[i] ^= mask[i];
        // }

        return BLOCK_SIZE - written_bytes;
    }

    void serialize_key_value(std::ostream&       out,
                             const keyword_type& k,
                             const TethysStashSerializationValue<value_type>& v)
    {
        encoder.serialize_key_value(out, k, v);
    }

    void start_tethys_encoding(const details::TethysGraph& g)
    {
        encoder.start_tethys_encoding(g);
    }

    void finish_tethys_table_encoding()
    {
        encoder.finish_tethys_table_encoding();
    }

    void finish_tethys_encoding()
    {
        encoder.finish_tethys_encoding();
    }

private:
    BaseEncoder encoder;
    key_type    encryption_key;
    // sse::crypto::Prf<BLOCK_SIZE> mask_prf;
};


template<class BaseDecoder, size_t BLOCK_SIZE>
class DecryptDecoder
{
public:
    // static constexpr size_t kKeySize =
    // sse::crypto::Prf<BLOCK_SIZE>::kKeySize; using key_type =
    // sse::crypto::Key<kKeySize>;
    static constexpr size_t kKeySize = crypto_stream_chacha20_KEYBYTES;
    using key_type                   = std::array<uint8_t, kKeySize>;

    static constexpr size_t kListControlValues
        = BaseDecoder::kListControlValues;

    using keyword_type = typename BaseDecoder::key_type;
    using value_type   = typename BaseDecoder::value_type;

    explicit DecryptDecoder(key_type key)
        : decoder(), decryption_key(std::move(key))
    {
    }
    // DecryptDecoder(key_type&& key) : decoder(), mask_prf(std::move(key))
    // {
    // }
    std::vector<value_type> decode_buckets(
        const keyword_type&                    key,
        const std::array<uint8_t, BLOCK_SIZE>& bucket_0,
        size_t                                 index_0,
        const std::array<uint8_t, BLOCK_SIZE>& bucket_1,
        size_t                                 index_1)
    {
        // start by decrypting the buckets
        // std::array<uint8_t, BLOCK_SIZE> mask_0 = mask_prf.prf(
        //     reinterpret_cast<uint8_t*>(&index_0), sizeof(size_t));

        // std::array<uint8_t, BLOCK_SIZE> mask_1 = mask_prf.prf(
        //     reinterpret_cast<uint8_t*>(&index_1), sizeof(size_t));


        std::array<uint8_t, BLOCK_SIZE> mask_0;
        std::array<uint8_t, BLOCK_SIZE> mask_1;
        // NOLINTNEXTLINE(modernize-avoid-c-arrays)
        uint8_t nonce[crypto_stream_chacha20_NONCEBYTES];

        memset(nonce, 0x00, sizeof(nonce));
        memcpy(nonce, reinterpret_cast<uint8_t*>(&index_0), sizeof(size_t));

        crypto_stream_chacha20(
            mask_0.data(), mask_0.size(), nonce, decryption_key.data());

        memset(nonce, 0x00, sizeof(nonce));
        memcpy(nonce, reinterpret_cast<uint8_t*>(&index_1), sizeof(size_t));

        crypto_stream_chacha20(
            mask_1.data(), mask_1.size(), nonce, decryption_key.data());


        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            mask_0[i] ^= bucket_0[i]; // to avoid copies, we put the result in
                                      // the keystream
        }

        for (size_t i = 0; i < BLOCK_SIZE; i++) {
            mask_1[i] ^= bucket_1[i]; // to avoid copies, we put the result in
                                      // the keystream
        }

        auto res
            = decoder.decode_buckets(key, mask_0, index_0, mask_1, index_1);

        sodium_memzero(mask_0.data(), mask_0.size());
        sodium_memzero(mask_1.data(), mask_1.size());

        return res;
    }

    std::pair<keyword_type, std::vector<value_type>> deserialize_key_value(
        std::istream& in)
    {
        keyword_type k;
        uint64_t     v_size = 0;

        std::vector<value_type> v;

        in.read(reinterpret_cast<char*>(&k), sizeof(k));

        // read the size of the vector
        in.read(reinterpret_cast<char*>(&v_size), sizeof(v_size));

        v.reserve(v_size);

        for (size_t i = 0; i < v_size; i++) {
            value_type elt;
            in.read(reinterpret_cast<char*>(&elt), sizeof(elt));
            v.push_back(elt);
        }

        return std::make_pair(k, v);
    }

private:
    BaseDecoder decoder;
    key_type    decryption_key;

    // sse::crypto::Prf<BLOCK_SIZE> mask_prf;
};

} // namespace encoders
} // namespace tethys
} // namespace sse