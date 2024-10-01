#pragma once
#include "json_serializer.hpp"

#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus/match.hpp>

#include <map>
struct DbusSerializer : JsonSerializer
{
    DbusSerializer(const std::string& path) : JsonSerializer(path) {}
    void addObjectAddMatch(sdbusplus::bus_t& bus, const std::string& path,
                           const std::string& interface,
                           std::function<void(const std::string&)> callback)
    {
        auto matchRule = sdbusplus::bus::match::rules::interfacesAdded(path);
        matches.emplace(
            std::piecewise_construct, std::forward_as_tuple(matchRule),
            std::forward_as_tuple(
                bus, matchRule.c_str(),
                std::bind_front(&DbusSerializer::addObjectHandler, this, path,
                                interface, std::move(callback))));
    }
    void addObjectHandler(const std::string& path, const std::string& interface,
                          std::function<void(const std::string&)> callback,
                          sdbusplus::message::message& msg)
    {
        try
        {
            sdbusplus::message::object_path objectPath;
            std::map<
                std::string,
                std::map<std::string, std::variant<std::string, int, bool>>>
                interfaces;
            msg.read(objectPath, interfaces);
            lg2::info("Object path: {PATH} Added", "PATH", objectPath);

            auto ifaces =
                interfaces |
                std::ranges::views::filter([&interface](const auto& i) {
                    return i.first == interface;
                });

            if (std::string_view(objectPath.str)
                    .starts_with(std::string(path)) &&
                !ifaces.empty())
            {
                callback(objectPath.str);
                store();
            }
        }
        catch (const std::exception& e)
        {
            lg2::error("Error while reading message: {ERR}", "ERR", e);
        }
    }
    void addObjectRemoveMatch(sdbusplus::bus_t& bus, const std::string& path,
                              const std::string& interface,
                              std::function<void(const std::string&)> callback)
    {
        auto matchRule = sdbusplus::bus::match::rules::interfacesRemoved(path);
        matches.emplace(
            std::piecewise_construct, std::forward_as_tuple(matchRule),
            std::forward_as_tuple(
                bus, matchRule.c_str(),
                std::bind_front(&DbusSerializer::removeObjectHandler, this,
                                path, interface, std::move(callback))));
    }
    void removeObjectHandler(const std::string& path,
                             const std::string& interface,
                             std::function<void(const std::string&)> callback,
                             sdbusplus::message::message& msg)
    {
        try
        {
            sdbusplus::message::object_path objectPath;
            std::vector<std::string> interfaces;
            msg.read(objectPath, interfaces);
            lg2::info("Object path: {PATH} Removed", "PATH", objectPath);
            auto ifaces =
                interfaces |
                std::ranges::views::filter([&interface](const auto& i) {
                    return i == interface;
                });

            if (std::string_view(objectPath.str)
                    .starts_with(std::string(path)) &&
                !ifaces.empty())
            {
                callback(objectPath.str);
                store();
            }
        }
        catch (const std::exception& e)
        {
            lg2::error("Error while reading message: {ERR}", "ERR", e);
        }
    }
    void addPropertyMatch(sdbusplus::bus_t& bus, const std::string& path,
                          const std::string& interface,
                          const std::string& property,
                          std::function<void(std::string_view)> callback)
    {
        std::string matchRule =
            sdbusplus::bus::match::rules::propertiesChanged(path, interface);
        auto propcallback = [callback = std::move(callback), property,
                             this](sdbusplus::message::message& msg) {
            std::string interfaceName;
            std::map<std::string, std::variant<std::string>> changedProperties;
            std::vector<std::string> invalidatedProperties;

            msg.read(interfaceName, changedProperties, invalidatedProperties);

            lg2::info("Properties changed on interface: {INTERFACENAME}",
                      "INTERFACENAME", interfaceName);

            changedProperties |
                std::ranges::views::filter(

                    [&property](const auto& p) { return p.first == property; });
            for (const auto& [prop, value] : changedProperties)
            {
                callback(std::get<std::string>(value));
                store();
            }
        };
        matches.emplace(std::piecewise_construct,
                        std::forward_as_tuple(matchRule),
                        std::forward_as_tuple(bus, matchRule.c_str(),
                                              std::move(propcallback)));
    }
    void removePropertyMatch(const std::string& path,
                             const std::string& interface)
    {
        std::string matchRule =
            sdbusplus::bus::match::rules::propertiesChanged(path, interface);
        matches.erase(matchRule);
    }

  private:
    std::map<std::string, sdbusplus::bus::match::match> matches;
};
