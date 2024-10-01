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

class JsonSerializer
{
  public:
    JsonSerializer(std::string path, nlohmann::json js = nlohmann::json()) :
        mfaConfPath(path), jsonData(std::move(js))
    {}

    inline auto stringSplitter()
    {
        return std::views::split('/') | std::views::transform([](auto&& sub) {
                   return std::string(sub.begin(), sub.end());
               });
    }
    nlohmann::json makeJson(const std::string& key, const std::string& value)
    {
        auto keys = key | stringSplitter();
        std::vector v(keys.begin(), keys.end());
        auto rv = v | std::views::reverse;
        nlohmann::json init;
        init[rv.front()] = value;
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
    void serialize(std::string key, const std::string value)
    {
        jsonData.merge_patch(makeJson(key, value));
    }
    template <typename T>
    void deserialize(std::string key, T& value)
    {
        auto leaf = getLeafNode(key);
        if (leaf)
        {
            value = *leaf;
        }
    }
    void erase(std::string key)
    {
        if (jsonData.contains(key))
        {
            jsonData.erase(key);
        }
    }
    bool store()
    {
        std::filesystem::path dir =
            std::filesystem::path(mfaConfPath).parent_path();

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
        std::ofstream file(mfaConfPath.data());
        if (file.is_open())
        {
            file << jsonData.dump(4); // Pretty print with 4 spaces
            file.close();
            return true;
        }
        else
        {
            lg2::error("Unable to open file {FILENAME}", "FILENAME",
                       mfaConfPath);
            return false;
        }
    }
    void load()
    {
        std::ifstream file(mfaConfPath.data());

        if (file.is_open())
        {
            file >> jsonData;
            file.close();
        }
        else
        {
            lg2::error("Unable to open file for reading {FILENAME}", "FILENAME",
                       mfaConfPath);
        }
    }

  private:
    const std::string mfaConfPath;
    nlohmann::json jsonData;
};
