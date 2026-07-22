#pragma once

#include <string_view>

#ifndef WPS_PROFILE_CIPHER_VERSION
#define WPS_PROFILE_CIPHER_VERSION "1.0.0"
#endif

namespace wps::profile
{

inline constexpr std::string_view version = WPS_PROFILE_CIPHER_VERSION;

} // namespace wps::profile
