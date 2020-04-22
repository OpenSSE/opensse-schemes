#pragma once

#include <sse/schemes/tethys/types.hpp>

#include <cstring>

#include <array>
#include <istream>
#include <ostream>

namespace sse {
namespace tethys {
namespace encoders {

template<class Key, class T, size_t PAGESIZE>
struct EncodeSeparateEncoder
{
    static constexpr size_t kAdditionalKeyEntriesPerList
        = sizeof(Key) / sizeof(T) + (sizeof(Key) % sizeof(T) == 0 ? 0 : 1);

    static constexpr size_t kListLengthEntriesNumber
        = sizeof(TethysAssignmentInfo::list_length) / sizeof(T)
          + (sizeof(TethysAssignmentInfo::list_length) % sizeof(T) == 0 ? 0
                                                                        : 1);

    static constexpr size_t kListControlValues
        = 2 * (kAdditionalKeyEntriesPerList + kListLengthEntriesNumber);

    static constexpr size_t kBucketControlValues = 1;

    size_t start_block_encoding(uint8_t* buffer, size_t table_index)
    {
        (void)buffer;
        (void)table_index;
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
            < kAdditionalKeyEntriesPerList + kListLengthEntriesNumber) {
            return 0;

            // for debugging only, not a valid encoding
            // std::fill(
            // buffer, buffer + infos.assigned_list_length * sizeof(T), 0xDD);
            // return infos.assigned_list_length * sizeof(T);
        }

        // we have to pay attention to the difference between the allocated list
        // size and the values' list size
        uint64_t encoded_list_size
            = infos.assigned_list_length
              - (kAdditionalKeyEntriesPerList
                 + kListLengthEntriesNumber); // we know this is positive
                                              // because of the previous test

        if (infos.dual_assigned_list_length
            < kAdditionalKeyEntriesPerList + kListLengthEntriesNumber) {
            // Some control blocks elements were spilled into our bucket
            // Do not consider them as real elements
            encoded_list_size -= kAdditionalKeyEntriesPerList
                                 + kListLengthEntriesNumber
                                 - infos.dual_assigned_list_length;
        }
        size_t encoded_list_offset = 0;

        if (infos.edge_orientation == IncomingEdge) {
            // Some of the first entries of the list might alread have been
            // encoded in an other bucket. infos.dual_assigned_list_length
            // (logical) elements have been allocated to the other bucket.

            // How many physical elements does that represent?
            if (infos.dual_assigned_list_length
                < kAdditionalKeyEntriesPerList + kListLengthEntriesNumber) {
                // no actual elements have been put in the other bucket
            } else {
                encoded_list_offset = infos.dual_assigned_list_length
                                      - (kAdditionalKeyEntriesPerList
                                         + kListLengthEntriesNumber);
            }
        }


        size_t offset = 0;

        // copy the length of the list
        std::copy(reinterpret_cast<const uint8_t*>(&encoded_list_size),
                  reinterpret_cast<const uint8_t*>(&encoded_list_size)
                      + sizeof(encoded_list_size),
                  buffer + offset);
        offset += sizeof(encoded_list_size); // offset = 8

        // fill with dummy bytes if needed
        std::fill(buffer + offset,
                  buffer + kAdditionalKeyEntriesPerList * sizeof(T),
                  0x11);
        offset = kListLengthEntriesNumber * sizeof(T); // offset = 8

        // copy the key
        std::copy(reinterpret_cast<const uint8_t*>(&key),
                  reinterpret_cast<const uint8_t*>(&key) + sizeof(Key),
                  buffer + offset);
        offset += sizeof(Key); // offset = 24


        // fill with dummy bytes if needed
        std::fill(
            buffer + offset, buffer + kListControlValues * sizeof(T), 0x22);
        offset = (kAdditionalKeyEntriesPerList + kListLengthEntriesNumber)
                 * sizeof(T); // offset = 24

        // now copy the values
        auto it_start = values.begin();


        it_start += encoded_list_offset;

        for (auto it = it_start; it != it_start + encoded_list_size; ++it) {
            T v = *it;
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

    void serialize_key_value(std::ostream&                           out,
                             const Key&                              k,
                             const TethysStashSerializationValue<T>& v)
    {
        out.write(reinterpret_cast<const char*>(k.data()), k.size());

        bool bucket_1_uf
            = (v.assignement_info.assigned_list_length
               < (kAdditionalKeyEntriesPerList + kListLengthEntriesNumber));

        bool bucket_2_uf
            = (v.assignement_info.dual_assigned_list_length
               < (kAdditionalKeyEntriesPerList + kListLengthEntriesNumber));


        size_t encoded_list_size_1 = 0;
        size_t encoded_list_size_2 = 0;

        if (!bucket_1_uf) {
            encoded_list_size_1
                = v.assignement_info.assigned_list_length
                  - (kAdditionalKeyEntriesPerList + kListLengthEntriesNumber);

            if (bucket_2_uf) {
                // Some control blocks elements of the second were spilled in
                // the first bucket Do not consider them as real elements
                encoded_list_size_1
                    -= kAdditionalKeyEntriesPerList + kListLengthEntriesNumber
                       - v.assignement_info.dual_assigned_list_length;
            }
        }
        if (!bucket_2_uf) {
            encoded_list_size_2
                = v.assignement_info.assigned_list_length
                  - (kAdditionalKeyEntriesPerList
                     + kListLengthEntriesNumber); // we know this is positive
                                                  // because of the previous
                                                  // test

            if (bucket_1_uf) {
                // Some control blocks elements of the second were spilled in
                // the first bucket Do not consider them as real elements
                encoded_list_size_2
                    -= kAdditionalKeyEntriesPerList + kListLengthEntriesNumber
                       - v.assignement_info.assigned_list_length;
            }
        }

        uint64_t v_size = v.assignement_info.list_length - kListControlValues
                          - encoded_list_size_1 - encoded_list_size_2;


        // write the size of the vector
        out.write(reinterpret_cast<const char*>(&v_size), sizeof(v_size));

        // and the elements
        for (auto it = v.data->end() - v_size; it != v.data->end(); ++it) {
            out.write(reinterpret_cast<const char*>(&(*it)), sizeof(*it));
        }
    }

    void start_tethys_encoding(const details::TethysGraph&)
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
    static constexpr size_t kAdditionalKeyEntriesPerList
        = EncodeSeparateEncoder<Key, T, PAGESIZE>::kAdditionalKeyEntriesPerList;


    static constexpr size_t kListLengthEntriesNumber
        = EncodeSeparateEncoder<Key, T, PAGESIZE>::kListLengthEntriesNumber;

    static constexpr size_t kListControlValues
        = EncodeSeparateEncoder<Key, T, PAGESIZE>::kListControlValues;

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
            } else {
                // jump to the next list
                offset += list_length * sizeof(T);
            }
        }
    }

    std::vector<T> decode_buckets(const Key&                           key,
                                  const std::array<uint8_t, PAGESIZE>& bucket_0,
                                  size_t,
                                  const std::array<uint8_t, PAGESIZE>& bucket_1,
                                  size_t)
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