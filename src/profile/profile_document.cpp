#include "wps_profile_cipher/profile_document.hpp"

#include <stdexcept>
#include <string>
#include <utility>

#include <SimpleIni.h>

namespace wps::profile
{
namespace
{

void sort_by_load_order(CSimpleIniA::TNamesDepend& names)
{
    names.sort(CSimpleIniA::Entry::LoadOrder {});
}

void require_success(const SI_Error result, const char* operation)
{
    if (result < 0)
    {
        throw std::runtime_error(std::string { "SimpleIni failed to " } + operation + '.');
    }
}

[[nodiscard]] std::string normalize_line_endings(std::string_view text, const std::string_view line_ending)
{
    std::string output;
    output.reserve(text.size());
    std::size_t consecutive_line_endings = 0;
    for (std::size_t index = 0; index < text.size(); ++index)
    {
        if (text[index] == '\r')
        {
            if (index + 1 < text.size() && text[index + 1] == '\n')
            {
                ++index;
            }
            ++consecutive_line_endings;
            if (consecutive_line_endings <= 2)
            {
                output += line_ending;
            }
        }
        else if (text[index] == '\n')
        {
            ++consecutive_line_endings;
            if (consecutive_line_endings <= 2)
            {
                output += line_ending;
            }
        }
        else
        {
            consecutive_line_endings = 0;
            output.push_back(text[index]);
        }
    }
    return output;
}

} // namespace

ProfileDocument ProfileDocument::parse(const std::string_view ini_text)
{
    CSimpleIniA ini { true, false, false };
    ini.SetQuotes(false);
    require_success(ini.LoadData(ini_text.data(), ini_text.size()), "parse the INI document");

    ProfileDocument document;
    CSimpleIniA::TNamesDepend section_names;
    ini.GetAllSections(section_names);
    sort_by_load_order(section_names);

    for (const auto& section_name : section_names)
    {
        CSimpleIniA::TNamesDepend key_names;
        static_cast<void>(ini.GetAllKeys(section_name.pItem, key_names));
        sort_by_load_order(key_names);

        if (section_name.pItem[0] == '\0')
        {
            if (!key_names.empty())
            {
                throw std::runtime_error("Invalid INI: entries must appear inside a section.");
            }
            continue;
        }

        ProfileSection section { section_name.pItem, {} };
        section.entries.reserve(key_names.size());
        for (const auto& key_name : key_names)
        {
            const auto* value = ini.GetValue(section_name.pItem, key_name.pItem, "");
            section.entries.push_back(ProfileEntry { key_name.pItem, value });
        }
        document.sections_.push_back(std::move(section));
    }
    return document;
}

const std::vector<ProfileSection>& ProfileDocument::sections() const noexcept { return sections_; }

std::vector<ProfileSection>& ProfileDocument::sections() noexcept { return sections_; }

std::string ProfileDocument::serialize(const LineEnding line_ending) const
{
    CSimpleIniA ini { true, false, false };
    ini.SetQuotes(false);
    ini.SetSpaces(true);

    for (const auto& section : sections_)
    {
        require_success(ini.SetValue(section.name.c_str(), nullptr, nullptr), "create an INI section");
        for (const auto& entry : section.entries)
        {
            require_success(ini.SetValue(section.name.c_str(), entry.key.c_str(), entry.value.c_str()), "write an INI entry");
        }
    }

    std::string output;
    require_success(ini.Save(output), "serialize the INI document");
    return normalize_line_endings(output, line_ending_text(line_ending));
}

} // namespace wps::profile
