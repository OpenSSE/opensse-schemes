#pragma once

#include <sse/schemes/tethys/types.hpp>

#include <cassert>
#include <cstring>

#include <array>
#include <istream>
#include <ostream>

namespace sse {
namespace tethys {
namespace encoders {

template<class Key, class T, size_t PAGESIZE>
struct EncodeSeparateDecoder;

template<class Key, class T, size_t PAGESIZE>
struct EncodeSeparateEncoder
{
    static constexpr size_t kEncodedPayloadSize = PAGESIZE;

    using key_type   = Key;
    using value_type = T;

    using decoder_type = EncodeSeparateDecoder<Key, T, PAGESIZE>;

    static constexpr size_t kAdditionalKeyEntriesPerList
        = sizeof(Key) / sizeof(T) + (sizeof(Key) % sizeof(T) == 0 ? 0 : 1);

    static constexpr size_t kListLengthEntriesNumber
        = sizeof(TethysAssignmentInfo::list_length) / sizeof(T)
          + (sizeof(TethysAssignmentInfo::list_length) % sizeof(T) == 0 ? 0
                                                                        : 1);

    static constexpr size_t kListControlValues
        = 2 * (kAdditionalKeyEntriesPerList + kListLengthEntriesNumber);

    static constexpr size_t kBucketControlValues = 0;

    size_t start_block_encoding(uint8_t* /*buffer*/, size_t /*table_index*/)
    {
        // (void)buffer;
        // (void)table_index;
        return 0;
    }

    size_t encode(uint8_t*              buffer,
                  size_t                table_index,
                  const Key&            key,
                  const std::vector<T>& values,
                  TethysAssignmentInfo  infos)
    {
        (void)table_index;
        if (infos.assigned_list_length
            <= kAdditionalKeyEntriesPerList + kListLengthEntriesNumber) {
            return 0;

            //         // for debugging only, not a valid encoding
            //         // std::fill(
            //         // buffer, buffer + infos.assigned_list_length *
            //         sizeof(T), 0xDD);
            //         // return infos.assigned_list_length * sizeof(T);
        }

        uint64_t original_list_size = infos.list_length - kListControlValues;

        // we have to pay attention to the difference between the allocated list
        // size and the values' list size
        uint64_t encoded_list_size
            = infos.assigned_list_length
              - (kAdditionalKeyEntriesPerList
                 + kListLengthEntriesNumber); // we know this is positive
                                              // because of the previous test

        // be sure we do not overflow the original list length by considering
        // spilled control values
        encoded_list_size = std::min(encoded_list_size, original_list_size);

        auto sublist_begin = values.begin();
        auto sublist_end   = values.end();
        // size_t sublist_begin = 0;
        // size_t sublist_end   = values.size();

        // the elements in the list are encoded the following order:
        // IncomingEdge || Stashed Edge || Outgoing Edge
        if (infos.edge_orientation == IncomingEdge) {
            sublist_end = values.begin() + encoded_list_size;
            // sublist_end = encoded_list_size;
        } else {
            sublist_begin = values.end() - encoded_list_size;
            // sublist_begin = values.size() - encoded_list_size;
        }


        size_t offset = 0;

        // copy the length of the list
        std::copy(reinterpret_cast<const uint8_t*>(&encoded_list_size),
                  reinterpret_cast<const uint8_t*>(&encoded_list_size)
                      + sizeof(encoded_list_size),
                  buffer + offset);
        offset += sizeof(encoded_list_size); // offset = 8

        // fill with dummy bytes if needed
        if (offset < kListLengthEntriesNumber * sizeof(T)) {
            std::fill(buffer + offset,
                      buffer + kAdditionalKeyEntriesPerList * sizeof(T),
                      0x11);
            offset = kListLengthEntriesNumber * sizeof(T); // offset = 8
        }

        // copy the key
        std::copy(reinterpret_cast<const uint8_t*>(&key),
                  reinterpret_cast<const uint8_t*>(&key) + sizeof(Key),
                  buffer + offset);
        offset += sizeof(Key); // offset = 24


        // fill with dummy bytes if needed
        if (offset < (kAdditionalKeyEntriesPerList + kListLengthEntriesNumber)
                         * sizeof(T)) {
            std::fill(
                buffer + offset, buffer + kListControlValues * sizeof(T), 0x22);
            offset = (kAdditionalKeyEntriesPerList + kListLengthEntriesNumber)
                     * sizeof(T); // offset = 24
        }
        // now copy the values
        for (auto it = sublist_begin; it != sublist_end; ++it) {
            const T& v = *it;

            std::copy(reinterpret_cast<const uint8_t*>(&v),
                      reinterpret_cast<const uint8_t*>(&v) + sizeof(T),
                      buffer + offset);
            offset += sizeof(T);
        }

        // // for debugging, paint the remaining with an other patter
        // // this is a not a valid encoding
        // std::fill(buffer + offset,
        //           buffer + infos.assigned_list_length * sizeof(T),
        //           0xDD);
        // return infos.assigned_list_length * sizeof(T);

        // std::cerr << offset << " / " << infos.list_length * sizeof(T) <<
        // "\n";

        // assert(offset <= infos.list_length * sizeof(T));

        return offset;
    }

    size_t finish_block_encoding(uint8_t* buffer,
                                 size_t   table_index,
                                 size_t   written_bytes,
                                 size_t   remaining_bytes)
    {
        (void)table_index;

        if (remaining_bytes == 0) {
            return 0;
        }

        memset(buffer + written_bytes, 0x00, remaining_bytes);
        return remaining_bytes;
    }

    // This is the serialization algorithm for the stash, called from
    // KVSerializer
    void serialize_key_value(std::ostream&                           out,
                             const Key&                              k,
                             const TethysStashSerializationValue<T>& v)
    {
        bool bucket_1_uf
            = (v.assignement_info.assigned_list_length
               <= (kAdditionalKeyEntriesPerList + kListLengthEntriesNumber));

        bool bucket_2_uf
            = (v.assignement_info.dual_assigned_list_length
               <= (kAdditionalKeyEntriesPerList + kListLengthEntriesNumber));


        size_t encoded_list_size_1 = 0;
        size_t encoded_list_size_2 = 0;

        if (!bucket_1_uf) {
            encoded_list_size_1
                = v.assignement_info.assigned_list_length
                  - (kAdditionalKeyEntriesPerList + kListLengthEntriesNumber);
        }
        if (!bucket_2_uf) {
            encoded_list_size_2
                = v.assignement_info.dual_assigned_list_length
                  - (kAdditionalKeyEntriesPerList
                     + kListLengthEntriesNumber); // we know this is
                                                  // positive because of the
                                                  // previous test
        }


        uint64_t original_list_size
            = v.assignement_info.list_length - kListControlValues;

        // be sure we do not overflow the original list length by considering
        // spilled control values
        encoded_list_size_1
            = std::min<uint64_t>(encoded_list_size_1, original_list_size);
        encoded_list_size_2
            = std::min<uint64_t>(encoded_list_size_2, original_list_size);


        uint64_t v_size = v.assignement_info.list_length - kListControlValues
                          - encoded_list_size_1 - encoded_list_size_2;

        if (v_size == 0) {
            return;
        }

        // write the key
        out.write(reinterpret_cast<const char*>(k.data()), k.size());

        // write the size of the vector
        out.write(reinterpret_cast<const char*>(&v_size), sizeof(v_size));

        // and the elements
        // for (auto it = v.data->begin() + encoded_list_size_1;
        //      it != v.data->end() - encoded_list_size_2;
        //      ++it) {

        const std::vector<T>& values = *(v.data);

        for (size_t i = encoded_list_size_1;
             i < values.size() - encoded_list_size_2;
             i++) {
            const T& elt = values[i];
            out.write(reinterpret_cast<const char*>(&elt), sizeof(elt));
        }
    }

    void start_tethys_encoding(const details::TethysGraph& /*g*/)
    {
    }

    void finish_tethys_table_encoding()
    {
    }

    void finish_tethys_encoding()
    {
    }
};


template<class Key, class T, size_t PAGESIZE>
struct EncodeSeparateDecoder
{
    using encoder_type = EncodeSeparateEncoder<Key, T, PAGESIZE>;


    static constexpr size_t kEncodedPayloadSize = PAGESIZE;

    static constexpr size_t kAdditionalKeyEntriesPerList
        = EncodeSeparateEncoder<Key, T, PAGESIZE>::kAdditionalKeyEntriesPerList;


    static constexpr size_t kListLengthEntriesNumber
        = EncodeSeparateEncoder<Key, T, PAGESIZE>::kListLengthEntriesNumber;

    static constexpr size_t kListControlValues
        = EncodeSeparateEncoder<Key, T, PAGESIZE>::kListControlValues;

    using key_type   = Key;
    using value_type = T;

    void decode_single_bucket(const Key&                           key,
                              const std::array<uint8_t, PAGESIZE>& bucket,
                              std::vector<T>& results) const
    {
        size_t offset = 0;

        Key      list_key;
        uint64_t list_length;

        while (offset < bucket.size()) {
            // read the length of the list
            memcpy(&list_length, bucket.data() + offset, sizeof(list_length));
            offset += sizeof(list_length);

            if (list_length == 0) {
                // we are at the end of the bucket
                break;
            }

            // read the key of the current list
            memcpy(&list_key, bucket.data() + offset, sizeof(list_key));
            offset += sizeof(list_key);

            if (list_key == key) {
                // match on the key
                results.reserve(results.size() + list_length);

                for (size_t i = 0; i < list_length; i++) {
                    T value;
                    memcpy(&value, bucket.data() + offset, sizeof(value));
                    offset += sizeof(value);

                    results.push_back(value);
                }

                break;
            }
            // jump to the next list
            offset += list_length * sizeof(T);
        }
    }

    std::vector<T> decode_buckets(const Key&                           key,
                                  const std::array<uint8_t, PAGESIZE>& bucket_0,
                                  size_t /*unused*/,
                                  const std::array<uint8_t, PAGESIZE>& bucket_1,
                                  size_t /*unused*/)
    {
        std::vector<T> res;

        decode_single_bucket(key, bucket_0, res);
        decode_single_bucket(key, bucket_1, res);
        return res;
    }

    std::pair<Key, std::vector<T>> deserialize_key_value(std::istream& in)
    {
        Key      k;
        uint64_t v_size = 0;

        std::vector<T> v;

        in.read(reinterpret_cast<char*>(&k), sizeof(k));

        // read the size of the vector
        in.read(reinterpret_cast<char*>(&v_size), sizeof(v_size));

        v.reserve(v_size);

        for (size_t i = 0; i < v_size; i++) {
            T elt;
            in.read(reinterpret_cast<char*>(&elt), sizeof(elt));
            v.push_back(elt);
        }

        return std::make_pair(k, v);
    }
};

} // namespace encoders
} // namespace tethys
} // namespace sse