#pragma once

#include "wps_profile_cipher/line_ending.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace wps::profile
{

struct ProfileEntry final
{
    std::string key;
    std::string value;

    friend bool operator==(const ProfileEntry&, const ProfileEntry&) = default;
};

struct ProfileSection final
{
    std::string name;
    std::vector<ProfileEntry> entries;

    friend bool operator==(const ProfileSection&, const ProfileSection&) = default;
};

class ProfileDocument final
{
public:
    [[nodiscard]] static ProfileDocument parse(std::string_view ini_text);

    [[nodiscard]] const std::vector<ProfileSection>& sections() const noexcept;
    [[nodiscard]] std::vector<ProfileSection>& sections() noexcept;
    [[nodiscard]] std::string serialize(LineEnding line_ending = LineEnding::native) const;

private:
    std::vector<ProfileSection> sections_;
};

} // namespace wps::profile
