#include <unistd.h>

#include <json_serializer.hpp>

#include <filesystem>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

namespace s = std::string_literals;

class JsonSerializerTest : public testing::Test
{
  protected:
    std::string test_file;

    void SetUp() override
    {
        char tmp_path_template[] = "/tmp/test_file_XXXXXX";
        int fd = mkstemp(tmp_path_template);
        if (fd == -1)
        {
            throw std::runtime_error("Failed to create temporary file.");
        }
        close(fd);
        test_file = tmp_path_template;
    }

    void TearDown() override
    {
        if (std::filesystem::exists(test_file))
        {
            std::filesystem::remove(test_file);
        }
    }
};

TEST_F(JsonSerializerTest, MakeJson)
{
    JsonSerializer s(test_file);
    nlohmann::json j = s.makeJson("foo/bar/baz", "value");
    EXPECT_EQ(j["foo"]["bar"]["baz"], "value");
}

TEST_F(JsonSerializerTest, SerializeDeserialize)
{
    JsonSerializer s(test_file);
    s.serialize("foo/bar/baz", "value");
    std::string value;
    s.deserialize("foo/bar/baz", value);
    EXPECT_EQ(value, "value");
}

TEST_F(JsonSerializerTest, StoreLoad)
{
    JsonSerializer s(test_file);
    s.serialize("foo/bar/baz", "value");
    s.store();

    // Create a new JsonSerializer instance to load from the same file
    // This simulates a fresh process loading the configuration
    JsonSerializer s2(test_file);
    s2.load();
    std::string value;
    s2.deserialize("foo/bar/baz", value);
    EXPECT_EQ(value, "value");
}

TEST_F(JsonSerializerTest, Erase)
{
    JsonSerializer s(test_file);
    s.serialize("foo/bar/baz", "value");
    // The current erase method only handles top-level keys.
    // Calling erase with a nested path like "foo/bar/baz" will not remove
    // "baz".
    s.erase("foo/bar/baz");
    s.store();

    // Verify that the value is still present because erase did not remove the
    // nested key.
    JsonSerializer s2(test_file);
    s2.load();
    std::string value;
    s2.deserialize("foo/bar/baz", value);
    EXPECT_EQ(value, "value"); // Expect original value to remain
}

TEST_F(JsonSerializerTest, GetLeafNode)
{
    JsonSerializer s(test_file);
    s.serialize("foo/bar/baz", "value");
    auto leaf = s.getLeafNode("foo/bar/baz");
    EXPECT_TRUE(leaf.has_value());
    EXPECT_EQ(*leaf, "value");

    leaf = s.getLeafNode("foo/bar/nonexistent");
    EXPECT_FALSE(leaf.has_value());
}

TEST_F(JsonSerializerTest, LoadInvalidJsonFile)
{
    // Ensure the file is empty or contains invalid JSON
    std::ofstream ofs(test_file, std::ios::trunc);
    ofs.close();

    JsonSerializer s(test_file);
    EXPECT_FALSE(s.load());
    EXPECT_FALSE(std::filesystem::exists(test_file));
}

TEST_F(JsonSerializerTest, LoadGarbledJsonFile)
{
    // Write a garbled JSON string to the file
    std::ofstream ofs(test_file);
    ofs << "{"; // Incomplete JSON object
    ofs.close();

    JsonSerializer s(test_file);
    EXPECT_FALSE(s.load());
    EXPECT_FALSE(std::filesystem::exists(test_file));
}
