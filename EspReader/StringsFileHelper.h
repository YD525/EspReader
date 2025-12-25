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

// Localized Strings Manager
class StringsManager
{
private:
    std::unordered_map<uint32_t, std::string> strings_;
    std::string currentLanguage_;

    // Check if file exists (compatible with older C++)
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

    // Extract directory from full path (compatible with older C++)
    std::string GetDirectory(const std::string& path) const
    {
        size_t pos = path.find_last_of("/\\");
        if (pos != std::string::npos)
        {
            return path.substr(0, pos);
        }
        return "";
    }

    // Extract file name from full path (without extension)
    std::string GetBaseName(const std::string& path) const
    {
        // Extract filename
        size_t pos = path.find_last_of("/\\");
        std::string filename = (pos != std::string::npos) ? path.substr(pos + 1) : path;

        // Remove extension
        pos = filename.find_last_of('.');
        if (pos != std::string::npos)
        {
            return filename.substr(0, pos);
        }
        return filename;
    }

    // Capitalize first letter
    std::string Capitalize(const std::string& str) const
    {
        if (str.empty()) return str;
        std::string result = str;
        result[0] = std::toupper(result[0]);
        return result;
    }

    // Build string file path
    std::string BuildStringsPath(const std::string& espPath,
        const std::string& language,
        const std::string& type) const
    {
        std::string dir = GetDirectory(espPath);
        std::string baseName = GetBaseName(espPath);
        std::string capitalizedLang = Capitalize(language);

        // Build path: Data/Strings/ModName_English.STRINGS
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

    // Load a single .STRINGS file
    bool LoadSingleStringsFile(const std::string& path)
    {
        std::ifstream file(path.c_str(), std::ios::binary);
        if (!file.is_open())
        {
            std::cerr << "Failed to open strings file: " << path << "\n";
            return false;
        }

        // Read file header
        uint32_t count, dataSize;
        file.read(reinterpret_cast<char*>(&count), 4);
        file.read(reinterpret_cast<char*>(&dataSize), 4);

        if (!file.good() || count == 0 || dataSize == 0)
        {
            std::cerr << "Invalid strings file header: " << path << "\n";
            file.close();
            return false;
        }

        // Read string directory (StringID + Offset pairs)
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

        // Read all string data
        std::vector<char> data(dataSize);
        file.read(data.data(), dataSize);
        file.close();

        if (data.empty())
        {
            std::cerr << "Failed to read string data: " << path << "\n";
            return false;
        }

        // Parse strings
        size_t loadedCount = 0;
        for (size_t i = 0; i < directory.size(); ++i)
        {
            uint32_t stringID = directory[i].first;
            uint32_t offset = directory[i].second;

            if (offset >= dataSize) continue;

            // Read length prefix (4 bytes)
            uint32_t length;
            std::memcpy(&length, data.data() + offset, 4);

            if (offset + 4 + length > dataSize) continue;

            // Extract string (UTF-8 or Windows-1252)
            std::string str(data.data() + offset + 4, length);

            // Remove null terminator
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

    // Extract StringID from data (4-byte uint32_t)
    static uint32_t GetStringID(const uint8_t* data, size_t size)
    {
        if (size < 4) return 0;
        uint32_t id;
        std::memcpy(&id, data, 4);
        return id;
    }

    // Load .STRINGS file
    // espPath: ESP file path, e.g., "C:/Data/3DNPC.esp"
    // language: language, e.g., "english", "chinese"
    bool LoadStringsFile(const std::string& espPath, const std::string& language = "english")
    {
        currentLanguage_ = language;
        strings_.clear();

        // Three types of strings files
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

    // Get string by ID
    std::string GetString(uint32_t stringID) const
    {
        std::unordered_map<uint32_t, std::string>::const_iterator it = strings_.find(stringID);
        if (it != strings_.end())
        {
            return it->second;
        }
        return "";
    }

    // Check if StringID exists
    bool HasString(uint32_t stringID) const
    {
        return strings_.count(stringID) > 0;
    }

    // Get string count
    size_t GetStringCount() const
    {
        return strings_.size();
    }

    // Clear all strings
    void Clear()
    {
        strings_.clear();
    }

    // Get current language
    std::string GetCurrentLanguage() const
    {
        return currentLanguage_;
    }
};
