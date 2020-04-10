#pragma once

#include <sse/schemes/abstractio/awonvm_vector.hpp>
#include <sse/schemes/oceanus/cuckoo.hpp>
#include <sse/schemes/oceanus/types.hpp>

#include <cassert>

#include <vector>

namespace sse {
namespace oceanus {

struct OceanusKeySerializer
{
    static constexpr size_t serialization_length()
    {
        return kTableKeySize;
    }
    void serialize(const key_type& key, uint8_t* buffer)
    {
        memcpy(buffer, key.data(), kTableKeySize);
    }
};

struct OceanusCuckooHasher
{
    CuckooKey operator()(const key_type& key)
    {
        CuckooKey ck;
        static_assert(sizeof(ck.h) == sizeof(key_type),
                      "Invalid source key size");

        memcpy(ck.h, key.data(), sizeof(ck.h));

        return ck;
    }
};

template<size_t PAGE_SIZE>
struct OceanusContentSerializer
{
    static constexpr size_t serialization_length()
    {
        return PAGE_SIZE - kOverhead * sizeof(index_type);
    }
    void serialize(const data_type<PAGE_SIZE>& value, uint8_t* buffer)
    {
        assert(value.size() * sizeof(typename data_type<PAGE_SIZE>::value_type)
               == serialization_length());
        memcpy(buffer,
               value.data(),
               value.size()
                   * sizeof(typename data_type<PAGE_SIZE>::value_type));
    }

    data_type<PAGE_SIZE> deserialize(const uint8_t* buffer)
    {
        data_type<PAGE_SIZE> res;
        memcpy(res.data(),
               buffer,
               res.size() * sizeof(typename data_type<PAGE_SIZE>::value_type));

        return res;
    }
};


template<size_t PAGE_SIZE>
class OceanusServerBuilder
{
public:
    using content_type       = data_type<PAGE_SIZE>;
    using content_serializer = OceanusContentSerializer<PAGE_SIZE>;

    OceanusServerBuilder(const std::string& db_path,
                         size_t             max_n_elements,
                         double             epsilon,
                         size_t             max_search_depth);
    ~OceanusServerBuilder();


    void insert(const std::array<uint8_t, kTableKeySize>& key,
                const data_type<PAGE_SIZE>&               value);

    void commit();


private:
    static CuckooBuilderParam make_cuckoo_builder_params(
        const std::string& base_path,
        size_t             max_n_elements,
        double             epsilon,
        size_t             max_search_depth)
    {
        CuckooBuilderParam params;
        params.value_file_path   = tmp_data_path(base_path);
        params.cuckoo_table_path = base_path;
        params.epsilon           = epsilon;
        params.max_n_elements    = max_n_elements;
        params.max_search_depth  = max_search_depth;

        return params;
    }

    static std::string tmp_data_path(std::string path)
    {
        return path.append(".tmp");
    }

    CuckooBuilderParam cuckoo_builder_params;

    CuckooBuilder<PAGE_SIZE,
                  key_type,
                  content_type,
                  OceanusKeySerializer,
                  content_serializer,
                  OceanusCuckooHasher>
        cuckoo_builder;
};


template<size_t PAGE_SIZE>
OceanusServerBuilder<PAGE_SIZE>::OceanusServerBuilder(
    const std::string& db_path,
    size_t             max_n_elements,
    double             epsilon,
    size_t             max_search_depth)
    : cuckoo_builder_params(make_cuckoo_builder_params(db_path,
                                                       max_n_elements,
                                                       epsilon,
                                                       max_search_depth)),
      cuckoo_builder(cuckoo_builder_params)
{
}

template<size_t PAGE_SIZE>
OceanusServerBuilder<PAGE_SIZE>::~OceanusServerBuilder()
{
    commit();
}


template<size_t PAGE_SIZE>
void OceanusServerBuilder<PAGE_SIZE>::commit()
{
    cuckoo_builder.commit();
}

template<size_t PAGE_SIZE>
void OceanusServerBuilder<PAGE_SIZE>::insert(
    const std::array<uint8_t, kTableKeySize>& key,
    const data_type<PAGE_SIZE>&               value)
{
    cuckoo_builder.insert(key, value);
}

} // namespace oceanus
} // namespace sse
