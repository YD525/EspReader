#pragma once
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <cstdint>
#include <vector>
#include <cstring>
#include <iostream>
#include <algorithm>
#include <cctype>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <dirent.h>
#endif

// 记录 Flag: 本地化字符串
constexpr uint32_t RECORD_FLAG_LOCALIZED = 0x00000080;

// 本地化字符串管理器
class StringsManager
{
private:
    std::unordered_map<uint32_t, std::string> strings_;
    std::string currentLanguage_;

    // 本地化字符串字段列表
    static const std::unordered_set<std::string>& GetLocalizedFields()
    {
        static std::unordered_set<std::string> fields = {
            "FULL", // Full Name
            "DESC", // Description
            "RNAM", // Response Text (INFO)
            "NAM1", // Prompt (INFO)
            "CNAM", // Journal Entry (QUST)
            "NNAM", // Display Name (QUST Stage)
            "ITXT", // Button Text (MESG)
            "DNAM", // Description (MGEF)
            "SHRT", // Short Name (NPC_)
            "TNAM", // Book Text (BOOK/NOTE)
            "RDMP", // Map Name (REGN)
            "EPF2", // Perk Effect Text
            "EPFD"  // Perk Effect Description
        };
        return fields;
    }

    // 检查文件是否存在 (兼容老版本 C++)
    bool FileExists(const std::string& path) const
    {
#ifdef _WIN32
        DWORD attr = GetFileAttributesA(path.c_str());
        return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
#else
        struct stat buffer;
        return (stat(path.c_str(), &buffer) == 0 && S_ISREG(buffer.st_mode));
#endif
    }

    // 从完整路径中提取目录 (兼容老版本 C++)
    std::string GetDirectory(const std::string& path) const
    {
        size_t pos = path.find_last_of("/\\");
        if (pos != std::string::npos)
        {
            return path.substr(0, pos);
        }
        return "";
    }

    // 从完整路径中提取文件名 (不含扩展名)
    std::string GetBaseName(const std::string& path) const
    {
        // 先提取文件名
        size_t pos = path.find_last_of("/\\");
        std::string filename = (pos != std::string::npos) ? path.substr(pos + 1) : path;

        // 移除扩展名
        pos = filename.find_last_of('.');
        if (pos != std::string::npos)
        {
            return filename.substr(0, pos);
        }
        return filename;
    }

    // 首字母大写
    std::string Capitalize(const std::string& str) const
    {
        if (str.empty()) return str;
        std::string result = str;
        result[0] = std::toupper(result[0]);
        return result;
    }

    // 构建字符串文件路径
    std::string BuildStringsPath(const std::string& espPath,
        const std::string& language,
        const std::string& type) const
    {
        std::string dir = GetDirectory(espPath);
        std::string baseName = GetBaseName(espPath);
        std::string capitalizedLang = Capitalize(language);

        // 构建路径: Data/Strings/ModName_English.STRINGS
        std::string stringsPath = dir;
        if (!stringsPath.empty())
        {
            stringsPath += "\\Strings\\";
        }
        else
        {
            stringsPath = "Strings\\";
        }

        stringsPath += baseName + "_" + capitalizedLang + "." + type;

        return stringsPath;
    }

    // 加载单个 .STRINGS 文件
    bool LoadSingleStringsFile(const std::string& path)
    {
        std::ifstream file(path.c_str(), std::ios::binary);
        if (!file.is_open())
        {
            std::cerr << "Failed to open strings file: " << path << "\n";
            return false;
        }

        // 读取文件头
        uint32_t count, dataSize;
        file.read(reinterpret_cast<char*>(&count), 4);
        file.read(reinterpret_cast<char*>(&dataSize), 4);

        if (!file.good() || count == 0 || dataSize == 0)
        {
            std::cerr << "Invalid strings file header: " << path << "\n";
            file.close();
            return false;
        }

        // 读取字符串目录 (StringID + Offset 对)
        std::vector<std::pair<uint32_t, uint32_t> > directory;
        directory.reserve(count);

        for (uint32_t i = 0; i < count; ++i)
        {
            uint32_t stringID, offset;
            file.read(reinterpret_cast<char*>(&stringID), 4);
            file.read(reinterpret_cast<char*>(&offset), 4);

            if (!file.good()) break;

            directory.push_back(std::make_pair(stringID, offset));
        }

        // 读取所有字符串数据
        std::vector<char> data(dataSize);
        file.read(data.data(), dataSize);
        file.close();

        if (data.empty())
        {
            std::cerr << "Failed to read string data: " << path << "\n";
            return false;
        }

        // 解析字符串
        size_t loadedCount = 0;
        for (size_t i = 0; i < directory.size(); ++i)
        {
            uint32_t stringID = directory[i].first;
            uint32_t offset = directory[i].second;

            if (offset >= dataSize) continue;

            // 读取长度前缀 (4 字节)
            uint32_t length;
            std::memcpy(&length, data.data() + offset, 4);

            if (offset + 4 + length > dataSize) continue;

            // 提取字符串 (UTF-8 或 Windows-1252)
            std::string str(data.data() + offset + 4, length);

            // 移除 null terminator
            if (!str.empty() && str[str.length() - 1] == '\0')
            {
                str.resize(str.length() - 1);
            }

            strings_[stringID] = str;
            loadedCount++;
        }

        std::cout << "Loaded " << loadedCount << " strings from: " << path << "\n";
        return true;
    }

public:
    StringsManager() : currentLanguage_("english") {}

    // 检查记录是否使用本地化字符串
    static bool IsLocalized(uint32_t flags)
    {
        return (flags & RECORD_FLAG_LOCALIZED) != 0;
    }

    // 检查字段是否为本地化字段
    static bool IsLocalizedField(const std::string& fieldSig)
    {
        return GetLocalizedFields().count(fieldSig) > 0;
    }

    // 从数据中提取 StringID (4字节 uint32_t)
    static uint32_t GetStringID(const uint8_t* data, size_t size)
    {
        if (size < 4) return 0;
        uint32_t id;
        std::memcpy(&id, data, 4);
        return id;
    }

    // 加载 .STRINGS 文件
    // espPath: ESP 文件路径，例如 "C:/Data/3DNPC.esp"
    // language: 语言，例如 "english", "chinese" 等
    bool LoadStringsFile(const std::string& espPath, const std::string& language = "english")
    {
        currentLanguage_ = language;
        strings_.clear();

        // 三种类型的字符串文件
        std::vector<std::string> types;
        types.push_back("STRINGS");
        types.push_back("DLSTRINGS");
        types.push_back("ILSTRINGS");

        bool loadedAny = false;
        for (size_t i = 0; i < types.size(); ++i)
        {
            std::string stringsPath = BuildStringsPath(espPath, language, types[i]);

            if (FileExists(stringsPath))
            {
                std::cout << "Found strings file: " << stringsPath << "\n";
                if (LoadSingleStringsFile(stringsPath))
                {
                    loadedAny = true;
                }
            }
            else
            {
                std::cout << "Strings file not found: " << stringsPath << "\n";
            }
        }

        std::cout << "Total strings loaded: " << strings_.size() << "\n";
        return loadedAny;
    }

    // 获取字符串
    std::string GetString(uint32_t stringID) const
    {
        std::unordered_map<uint32_t, std::string>::const_iterator it = strings_.find(stringID);
        if (it != strings_.end())
        {
            return it->second;
        }
        return "";
    }

    // 检查 StringID 是否存在
    bool HasString(uint32_t stringID) const
    {
        return strings_.count(stringID) > 0;
    }

    // 获取字符串数量
    size_t GetStringCount() const
    {
        return strings_.size();
    }

    // 清空所有字符串
    void Clear()
    {
        strings_.clear();
    }

    // 获取当前语言
    std::string GetCurrentLanguage() const
    {
        return currentLanguage_;
    }
};