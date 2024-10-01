#pragma once
#include "json_serializer.hpp"

#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus/match.hpp>
struct DbusSerializer : JsonSerializer
{
    DbusSerializer(const std::string& path) : JsonSerializer(path) {}
    void addObjectAddMatch(sdbusplus::bus_t& bus, const std::string& path,
                           const std::string& interface,
                           std::function<void(const std::string&)> callback)
    {
        addObjectMatch(bus, path, true, interface, std::move(callback));
    }
    void addObjectRemoveMatch(sdbusplus::bus_t& bus, const std::string& path,
                              const std::string& interface,
                              std::function<void(const std::string&)> callback)
    {
        addObjectMatch(bus, path, false, interface, std::move(callback));
    }
    void addObjectMatch(sdbusplus::bus_t& bus, const std::string& path,
                        bool add, const std::string& interface,
                        std::function<void(const std::string&)> callback)
    {
        std::string matchRule = std::format(
            "{}", add ? sdbusplus::bus::match::rules::interfacesAdded(path)
                      : sdbusplus::bus::match::rules::interfacesRemoved(path));

        auto objcallback = [this, interface, path,
                            callback = std::move(callback)](
                               sdbusplus::message::message& msg) {
            try
            {
                sdbusplus::message::object_path objectPath;
                std::map<
                    std::string,
                    std::map<std::string, std::variant<std::string, int, bool>>>
                    interfaces;
                msg.read(objectPath, interfaces);
                lg2::info("Object path: {PATH}", "PATH", objectPath);

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
        };
        matches.emplace_back(bus, matchRule.c_str(), std::move(objcallback));
    }
    void addPropertyMatch(sdbusplus::bus_t& bus, const std::string& path,
                          const std::string& interface,
                          const std::string& property,
                          std::function<void(std::string_view)> callback)
    {
        std::string matchRule = std::format(
            R"(type='signal',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged',path='{}',arg0='{}')",
            path, interface);

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
        matches.emplace_back(bus, matchRule.c_str(), std::move(propcallback));
    }

  private:
    std::vector<sdbusplus::bus::match::match> matches;
};
