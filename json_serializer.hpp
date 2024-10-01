#pragma once

#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>

#include <format>
#include <fstream>
#include <ranges>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>

template <typename T>
using remove_const_and_reference_t =
    std::remove_const_t<std::remove_reference_t<T>>;

template <typename T>
inline constexpr bool isConvertibleToConstCharPtrV =
    std::is_convertible_v<T, const char*>;

template <typename T>
concept StringType =
    requires(T t) {
        requires std::is_same_v<remove_const_and_reference_t<T>, const char*> or
                     std::is_same_v<remove_const_and_reference_t<T>,
                                    std::string> or
                     std::is_same_v<remove_const_and_reference_t<T>,
                                    std::string_view> or
                     isConvertibleToConstCharPtrV<T>;
    };

template <typename Value>
struct KVPair
{
    KVPair(std::string_view n, Value v) :
        name(n.data(), n.length()), value(std::move(v))
    {}
    std::string name;
    Value value;
};

template <typename T>
struct IsTupleOfLength2 : std::false_type
{};

// Specialization for std::tuple
template <typename T1, typename T2>
struct IsTupleOfLength2<std::tuple<T1, T2>> : std::true_type
{};

// Helper variable template

template <typename T>
concept TuplePair =
    requires(T t) {
        requires StringType<
                     typename std::tuple_element<0, decltype(t)>::type> and
                     IsTupleOfLength2<T>::value;
    };

template <typename T>
struct IsOptional : std::false_type
{};

template <typename T>
struct IsOptional<std::optional<T>> : std::true_type
{};

class JsonSerializer
{
  public:
    JsonSerializer(std::string path, nlohmann::json js = nlohmann::json()) :
        mfa_conf_path(path), jsonData(std::move(js))
    {}
    inline auto stringSplitter()
    {
        return std::views::split('/') | std::views::transform([](auto&& sub) {
                   return std::string(sub.begin(), sub.end());
               });
    }
    template <typename T>
    auto makeJson(const KVPair<T>& d)
    {
        auto keys = d.name | stringSplitter();
        std::vector v(keys.begin(), keys.end());
        auto rv = v | std::views::reverse;
        nlohmann::json init;
        init[rv.front()] = d.value;
        auto newJson = std::reduce(rv.begin() + 1, rv.end(), init,
                                   [](auto sofar, auto currentKey) {
                                       nlohmann::json j;
                                       j[currentKey] = sofar;
                                       return j;
                                   });
        return newJson;
    }
    std::optional<nlohmann::json> getLeafNode(const std::string_view keyPath)
    {
        auto keys = keyPath | stringSplitter();
        nlohmann::json current = jsonData;
        for (auto key : keys)
        {
            if (!current.contains(key))
            {
                return std::nullopt;
            }
            current = current[key];
        }
        return current;
    }

    template <typename... Args>
    void serialize(Args&&... args)
    {
        if constexpr (sizeof...(args) == 0)
        {
            return;
        }
        static_assert(sizeof...(args) % 2 == 0,
                      "Arguments should be in key-value pairs");
        serialize(std::forward<Args>(args)...);
    }
    template <typename Key, typename Value, typename... Args>
    void serialize(Key&& key, Value&& value, Args&&... args)
    {
        static_assert(StringType<Key>, "Key must satisfy StringType concept");

        jsonData.merge_patch(makeJson(
            KVPair{std::forward<Key>(key), std::forward<Value>(value)}));
        serialize(std::forward<Args>(args)...);
    }
    template <TuplePair... Pairs>
    void deserializeImpl(Pairs&&... data)
    {
        if constexpr (sizeof...(data) > 0)
        {
            auto tempfunc = [this](auto&& tup) {
                using tuptype = remove_const_and_reference_t<decltype(tup)>;
                using Type = typename std::tuple_element<1, tuptype>::type;
                auto leaf = getLeafNode(std::get<0>(tup));
                if constexpr (IsOptional<
                                  remove_const_and_reference_t<Type>>::value)
                {
                    try
                    {
                        if (leaf)
                        {
                            std::get<1>(tup) = *leaf;
                        }
                        else
                        {
                            std::get<1>(tup) = std::nullopt;
                        }
                    }
                    catch (...)
                    {
                        std::get<1>(tup) = std::nullopt;
                    }
                }
                else
                {
                    std::get<1>(tup) = *leaf;
                }
            };
            (tempfunc(data), ...);
        }
    }
    template <typename... Args>
    void deserialize(Args&&... args)
    {
        deserializeImpl(std::forward<Args>(args)...);
    }
    template <StringType Key, typename Value, typename... Args>
    void deserialize(Key&& key, Value& value, Args&&... args)
    {
        deserializeImpl(std::tie(key, value));
        deserialize(std::forward<Args>(args)...);
    }

    bool store()
    {
        std::filesystem::path dir =
            std::filesystem::path(mfa_conf_path).parent_path();

        // Check if the directory exists, and create it if it does not
        if (!dir.string().empty() && !std::filesystem::exists(dir))
        {
            std::error_code ec;
            if (!std::filesystem::create_directories(dir, ec))
            {
                lg2::error("Unable to create directory {DIR}", "DIR",
                           dir.string());
                return false;
            }
        }
        std::ofstream file(mfa_conf_path.data());
        if (file.is_open())
        {
            file << jsonData.dump(4); // Pretty print with 4 spaces
            file.close();
            return true;
        }
        else
        {
            lg2::error("Unable to open file {FILENAME}", "FILENAME",
                       mfa_conf_path);
            return false;
        }
    }
    void load()
    {
        std::ifstream file(mfa_conf_path.data());

        if (file.is_open())
        {
            file >> jsonData;
            file.close();
        }
        else
        {
            lg2::error("Unable to open file for reading {FILENAME}", "FILENAME",
                       mfa_conf_path);
        }
    }

  private:
    const std::string mfa_conf_path;
    nlohmann::json jsonData;
};
