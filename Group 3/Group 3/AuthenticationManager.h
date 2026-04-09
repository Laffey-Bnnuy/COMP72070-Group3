#pragma once

#include <string>

class AuthenticationManager
{
public:

    bool authenticate(
        const std::string& u,
        const std::string& p)
    {
        return u == "admin"
            && p == "1234";
    }
};
