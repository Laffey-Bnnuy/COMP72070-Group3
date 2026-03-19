#pragma once
#include <string>
#include <map>

class AuthenticationManager
{
private:

    std::map<std::string, std::string> users;

public:

    AuthenticationManager()
    {
        users["admin"] = "1234";
        users["user"] = "pass";
    }

    bool authenticate(std::string user,
                      std::string pass)
    {
        if (users.count(user) == 0)
            return false;

        return users[user] == pass;
    }
};
