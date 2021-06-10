#pragma once

#include <functional>
#include <istream>
#include <map>
#include <ostream>

namespace sse {
namespace abstractio {

template<class Key, class T, class InnerSerializer>
class KVSerializer
{
public:
    explicit KVSerializer(std::ostream& s) : out_stream(s)
    {
    }

    void serialize(const Key& k, const T& v, InnerSerializer& serializer)
    {
        serializer.serialize_key_value(out_stream, k, v);
    }

    // useful overloads
    void serialize(const Key& k, const T& v)
    {
        InnerSerializer serializer;
        serialize(k, v, serializer);
    }


    template<class KVType>
    void serialize(const KVType& kv, InnerSerializer& serializer)
    {
        serialize(kv.get_key(), kv.get_value(), serializer);
    }
    template<class KVType>
    void serialize(const KVType& kv)
    {
        InnerSerializer serializer;
        serialize(kv.get_key(), kv.get_value(), serializer);
    }


    template<class K, class V>
    void serialize(const std::pair<K, V>& kv, InnerSerializer& serializer)
    {
        serialize(kv.first, kv.second, serializer);
    }
    template<class K, class V>
    void serialize(const std::pair<K, V>& kv)
    {
        InnerSerializer serializer;
        serialize(kv.first, kv.second, serializer);
    }

    template<class Iterable>
    void serialize_iterable(const Iterable& data, InnerSerializer& serializer)
    {
        for (const auto& kv : data) {
            serialize(kv, serializer);
        }
    }

    template<class Iterable>
    void serialize_iterable(const Iterable& data)
    {
        InnerSerializer serializer;
        serialize_iterable(data, serializer);
    }

private:
    std::ostream& out_stream;
};

template<class Key, class T, class InnerDeserializer>
void deserialize(std::istream&                   input_stream,
                 std::function<void(Key k, T v)> callback,
                 InnerDeserializer&              deserializer)
{
    while (input_stream && input_stream.peek() != EOF) {
        std::pair<Key, T> kv = deserializer.deserialize_key_value(input_stream);
        callback(std::move(kv.first), std::move(kv.second));
    }
}
template<class Key, class T, class InnerDeserializer>
void deserialize(std::istream&                   input_stream,
                 std::function<void(Key k, T v)> callback)
{
    deserialize<Key, T, InnerDeserializer>(
        input_stream, callback, InnerDeserializer());
}

template<class Key, class T, class InnerDeserializer>
std::map<Key, T> deserialize_map(std::istream&      input_stream,
                                 InnerDeserializer& deserializer)
{
    std::map<Key, T> result;
    auto             cb = [&result](Key k, T v) {
        // insert the results in the map
        result[std::move(k)] = std::move(v);
    };
    deserialize<Key, T, InnerDeserializer>(input_stream, cb, deserializer);

    return result;
}
template<class Key, class T, class InnerDeserializer>
std::map<Key, T> deserialize_map(std::istream& input_stream)
{
    InnerDeserializer deser;

    return deserialize_map<Key, T, InnerDeserializer>(input_stream, deser);
}

} // namespace abstractio
} // namespace sse