#pragma once

#include <sse/schemes/abstractio/awonvm_vector.hpp>
#include <sse/schemes/oceanus/details/cuckoo.hpp>
#include <sse/schemes/utils/optional.hpp>

#include <cmath>

#include <vector>

namespace sse {
namespace oceanus {

struct CuckooBuilderParam
{
    std::string value_file_path;
    std::string table_0_path;
    std::string table_1_path;

    size_t max_n_elements;
    double epsilon;
    size_t max_search_depth;

    size_t table_size() const
    {
        return details::cuckoo_table_size(max_n_elements, epsilon);
    }
};

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class KeySerializer,
         class ValueSerializer,
         class CuckooHasher>
class CuckooBuilder
{
public:
    static constexpr size_t kKeySize = KeySerializer::serialization_length();
    static constexpr size_t kValueSize
        = ValueSerializer::serialization_length();
    static constexpr size_t kPayloadSize = kValueSize + kKeySize;
    static_assert(kPayloadSize % PAGE_SIZE == 0,
                  "Cuckoo payload size incompatible with the page size");

    using payload_type = std::array<uint8_t, kPayloadSize>;

    explicit CuckooBuilder(CuckooBuilderParam p);
    ~CuckooBuilder();

    void insert(const Key& key, const T& val);

    void commit();

private:
    CuckooBuilderParam params;

    details::CuckooAllocator                           allocator;
    abstractio::awonvm_vector<payload_type, PAGE_SIZE> data;

    std::vector<size_t> spilled_data;

    size_t n_elements;
    bool   is_committed{false};
};

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class KeySerializer,
         class ValueSerializer,
         class CuckooHasher>
constexpr size_t CuckooBuilder<PAGE_SIZE,
                               Key,
                               T,
                               KeySerializer,
                               ValueSerializer,
                               CuckooHasher>::kKeySize;

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class KeySerializer,
         class ValueSerializer,
         class CuckooHasher>
constexpr size_t CuckooBuilder<PAGE_SIZE,
                               Key,
                               T,
                               KeySerializer,
                               ValueSerializer,
                               CuckooHasher>::kValueSize;

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class KeySerializer,
         class ValueSerializer,
         class CuckooHasher>
constexpr size_t CuckooBuilder<PAGE_SIZE,
                               Key,
                               T,
                               KeySerializer,
                               ValueSerializer,
                               CuckooHasher>::kPayloadSize;


template<size_t PAGE_SIZE,
         class Key,
         class T,
         class KeySerializer,
         class ValueSerializer,
         class CuckooHasher>
CuckooBuilder<PAGE_SIZE, Key, T, KeySerializer, ValueSerializer, CuckooHasher>::
    CuckooBuilder(CuckooBuilderParam p)
    : params(std::move(p)),
      allocator(params.table_size(), params.max_search_depth),
      data(params.value_file_path), spilled_data(), n_elements(0)
{
    data.reserve(params.max_n_elements);
}

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class KeySerializer,
         class ValueSerializer,
         class CuckooHasher>
CuckooBuilder<PAGE_SIZE, Key, T, KeySerializer, ValueSerializer, CuckooHasher>::
    ~CuckooBuilder()
{
    if (!is_committed) {
        commit();
    }
}


template<size_t PAGE_SIZE,
         class Key,
         class T,
         class KeySerializer,
         class ValueSerializer,
         class CuckooHasher>
void CuckooBuilder<PAGE_SIZE,
                   Key,
                   T,
                   KeySerializer,
                   ValueSerializer,
                   CuckooHasher>::insert(const Key& key, const T& val)
{
    if (is_committed) {
        throw std::runtime_error(
            "The Cuckoo builder has already been commited");
    }

    payload_type payload;

    KeySerializer   key_serializer;
    ValueSerializer value_serializer;
    CuckooHasher    hasher;

    key_serializer.serialize(key, payload.data());
    value_serializer.serialize(val, payload.data() + kKeySize);

    size_t value_ptr = data.push_back(payload);

    CuckooKey cuckoo_key = hasher(key);

    size_t spill = allocator.insert(cuckoo_key, value_ptr);

    if (!details::CuckooAllocator::is_empty_placeholder(spill)) {
        std::cerr << "Spill!\n";
        spilled_data.push_back(spill);
    } else {
        // std::cerr << "No spill\n";
    }
}

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class KeySerializer,
         class ValueSerializer,
         class CuckooHasher>
void CuckooBuilder<PAGE_SIZE,
                   Key,
                   T,
                   KeySerializer,
                   ValueSerializer,
                   CuckooHasher>::commit()
{
    if (is_committed) {
        return;
    }

    is_committed = true;

    // commit the data file
    data.commit();

    // create two new files: one per table

    abstractio::awonvm_vector<payload_type, PAGE_SIZE> table_0(
        params.table_0_path);

    abstractio::awonvm_vector<payload_type, PAGE_SIZE> table_1(
        params.table_1_path);

    table_0.reserve(allocator.get_cuckoo_table_size());
    table_1.reserve(allocator.get_cuckoo_table_size());

    payload_type empty_content;

    std::fill(empty_content.begin(), empty_content.end(), 0xFF);

    for (auto it = allocator.table_0_begin(); it != allocator.table_0_end();
         ++it) {
        size_t loc = it->value_index;

        if (details::CuckooAllocator::is_empty_placeholder(loc)) {
            table_0.push_back(empty_content);
        } else {
            payload_type pl = data.get(loc);
            table_0.push_back(pl);
        }
    }
    for (auto it = allocator.table_1_begin(); it != allocator.table_1_end();
         ++it) {
        size_t loc = it->value_index;

        if (details::CuckooAllocator::is_empty_placeholder(loc)) {
            table_1.push_back(empty_content);
        } else {
            payload_type pl = data.get(loc);
            table_1.push_back(pl);
        }
    }
    table_0.commit();
    table_1.commit();
}

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class KeySerializer,
         class ValueSerializer,
         class CuckooHasher>
class CuckooHashTable
{
public:
    static constexpr size_t kKeySize = CuckooBuilder<PAGE_SIZE,
                                                     Key,
                                                     T,
                                                     KeySerializer,
                                                     ValueSerializer,
                                                     CuckooHasher>::kKeySize;
    static constexpr size_t kValueSize
        = CuckooBuilder<PAGE_SIZE,
                        Key,
                        T,
                        KeySerializer,
                        ValueSerializer,
                        CuckooHasher>::kValueSize;
    static constexpr size_t kPayloadSize
        = CuckooBuilder<PAGE_SIZE,
                        Key,
                        T,
                        KeySerializer,
                        ValueSerializer,
                        CuckooHasher>::kPayloadSize;
    using payload_type = typename CuckooBuilder<PAGE_SIZE,
                                                Key,
                                                T,
                                                KeySerializer,
                                                ValueSerializer,
                                                CuckooHasher>::payload_type;

    using get_callback_type
        = std::function<void(std::experimental::optional<T>)>;


    CuckooHashTable(const std::string& table_0_path,
                    const std::string& table_1_path);


    T    get(const Key& key);
    void async_get(const Key& key, get_callback_type callback);


    void use_direct_IO(bool flag);

private:
    abstractio::awonvm_vector<payload_type, PAGE_SIZE> table_0;
    abstractio::awonvm_vector<payload_type, PAGE_SIZE> table_1;

    size_t table_size;
};

template<size_t PAGE_SIZE,
         class Key,
         class T,
         class KeySerializer,
         class ValueSerializer,
         class CuckooHasher>
CuckooHashTable<PAGE_SIZE,
                Key,
                T,
                KeySerializer,
                ValueSerializer,
                CuckooHasher>::CuckooHashTable(const std::string& table_0_path,
                                               const std::string& table_1_path)
    : table_0(table_0_path, false), table_1(table_1_path, false)
{
    if (!table_0.is_committed()) {
        throw std::runtime_error("Table 0 not committed");
    }
    if (!table_1.is_committed()) {
        throw std::runtime_error("Table 1 not committed");
    }

    table_size = table_0.size();

    if (table_size != table_1.size()) {
        throw std::runtime_error("Invalid Cuckoo table sizes");
    }

    std::cerr << "Cuckoo hash table initialization succeeded!\n";
    std::cerr << "Table size: " << table_size << "\n";
}


template<size_t PAGE_SIZE,
         class Key,
         class T,
         class KeySerializer,
         class ValueSerializer,
         class CuckooHasher>
T CuckooHashTable<PAGE_SIZE,
                  Key,
                  T,
                  KeySerializer,
                  ValueSerializer,
                  CuckooHasher>::get(const Key& key)
{
    CuckooKey search_key = CuckooHasher()(key);

    // look in the first table
    size_t loc = search_key.h[0] % table_size;

    std::array<uint8_t, kKeySize> ser_key;
    KeySerializer().serialize(key, ser_key.data());

    payload_type val_0 = table_0.get(loc);
    if (details::match_key<PAGE_SIZE>(val_0, ser_key)) {
        return ValueSerializer().deserialize(val_0.data() + kKeySize);
    } else {
        loc = search_key.h[1] % table_size;

        payload_type val_1 = table_1.get(loc);

        if (details::match_key<PAGE_SIZE>(val_1, ser_key)) {
            return ValueSerializer().deserialize(val_1.data() + kKeySize);
        } else {
            throw std::out_of_range("Key not found");
        }
    }
}


template<size_t PAGE_SIZE,
         class Key,
         class T,
         class KeySerializer,
         class ValueSerializer,
         class CuckooHasher>
void CuckooHashTable<PAGE_SIZE,
                     Key,
                     T,
                     KeySerializer,
                     ValueSerializer,
                     CuckooHasher>::async_get(const Key&        key,
                                              get_callback_type callback)
{
    struct CallBackState
    {
        std::unique_ptr<payload_type> result{nullptr};
        std::atomic_uint8_t           completion_counter{0};
    };

    CuckooKey search_key = CuckooHasher()(key);

    // generate both locations
    size_t loc_0 = search_key.h[0] % table_size;
    size_t loc_1 = search_key.h[1] % table_size;

    std::array<uint8_t, kKeySize> ser_key;
    KeySerializer().serialize(key, ser_key.data());

    CallBackState* state = new CallBackState();

    auto inner_callback =
        [state, ser_key, callback](std::unique_ptr<payload_type> read_value) {
            if (read_value) {
                // check whether we are a match on the key
                if (details::match_key<PAGE_SIZE>(*read_value.get(), ser_key)) {
                    // only one of the two callback should access this
                    // section
                    // no need for a mutex
                    state->result = std::move(read_value);
                }
            }


            uint8_t completed = state->completion_counter.fetch_add(1);

            if (completed == 1) {
                // We can use the caller callback, and delete the state
                // Be careful though: we want to destruct the state before we
                // calling the callback, while still having a pointer to the
                // retrieved data
                // So we first need to move the smart pointer.

                // Also, why putting the retrieved data in the state and not
                // in the local callback state? Think about when none of the
                // fetched value match the searched key: we still have to
                // return the (empty) result to the outer callback, and this
                // can only be done by the last running inner callback. Thus
                // we will communication channel between both inner callbacks.
                // Although this might be done with a smaller overhead than
                // using a unique_ptr (eg. using the completion counter as an
                // additional flag), this is its role for the moment.

                std::unique_ptr<payload_type> data = std::move(state->result);

                delete state;

                if (data) {
                    callback(
                        ValueSerializer().deserialize(data->data() + kKeySize));
                } else {
                    callback(std::experimental::nullopt);
                }
            }
        };


    table_0.async_get(loc_0, inner_callback);
    table_1.async_get(loc_1, inner_callback);
}


template<size_t PAGE_SIZE,
         class Key,
         class T,
         class KeySerializer,
         class ValueSerializer,
         class CuckooHasher>
void CuckooHashTable<PAGE_SIZE,
                     Key,
                     T,
                     KeySerializer,
                     ValueSerializer,
                     CuckooHasher>::use_direct_IO(bool flag)
{
    table_0.set_use_direct_access(flag);
    table_1.set_use_direct_access(flag);
}


} // namespace oceanus
} // namespace sse
