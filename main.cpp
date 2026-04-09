#include <iostream>
#include <string>
#include "SocketHandler.h"
#include "CommandProcessor.h"
#include "Server.h"

int main(int argc, char* argv[])
{
    if (argc > 1 && std::string(argv[1]) == "--server")
    {
        Server s;
        s.start();
        return 0;
    }

    std::string host = "127.0.0.1";
    int         port = 54000;

    std::cout << "  COMP72070 Group 3 - File Client  \n";
    std::cout << "Server: " << host << ":" << port << "\n";

    SocketHandler    sock;
    CommandProcessor cmd(sock);

    if (!cmd.connectToServer(host, port))
    {
        std::cout << "[FATAL] Could not connect to server\n";
        return 1;
    }

    const int MAX_ATTEMPTS = 3;
    bool loggedIn = false;
    for (int attempt = 0; attempt < MAX_ATTEMPTS; ++attempt)
    {
        std::string username, password;
        std::cout << "\nUsername: ";
        std::getline(std::cin, username);
        std::cout << "Password: ";
        std::getline(std::cin, password);

        if (cmd.login(username, password))
        {
            loggedIn = true;
            break;
        }

        int remaining = MAX_ATTEMPTS - attempt - 1;
        if (remaining > 0)
            std::cout << "[AUTH] " << remaining << " attempt(s) remaining\n";
    }

    if (!loggedIn)
    {
        std::cout << "[FATAL] Authentication failed - disconnecting\n";
        cmd.disconnect();
        return 1;
    }

    std::cout << "\nReady. Commands:\n"
        << "  GET <remote> [local]       download a file\n"
        << "  PUT <local>  [remote]      upload a file\n"
        << "  MODE READONLY              switch server to read-only mode\n"
        << "  MODE READWRITE             switch server to read-write mode\n"
        << "  quit                       exit\n";

    while (true)
    {
        std::cout << "\n> ";
        std::string line;
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        size_t      sp   = line.find(' ');
        std::string verb = (sp == std::string::npos) ? line : line.substr(0, sp);
        std::string rest = (sp == std::string::npos) ? "" : line.substr(sp + 1);

        if (verb == "quit" || verb == "exit" || verb == "q")
            break;

        auto splitTwo = [](const std::string& s, std::string& a, std::string& b) {
            size_t sp2 = s.find(' ');
            a = (sp2 == std::string::npos) ? s : s.substr(0, sp2);
            b = (sp2 == std::string::npos) ? a : s.substr(sp2 + 1);
        };

        if (verb == "GET" || verb == "get")
        {
            if (rest.empty()) { std::cout << "Usage: GET <remote> [local]\n"; continue; }
            std::string remote, local;
            splitTwo(rest, remote, local);
            cmd.getFile(remote, local);
        }
        else if (verb == "PUT" || verb == "put")
        {
            if (rest.empty()) { std::cout << "Usage: PUT <local> [remote]\n"; continue; }
            std::string local, remote;
            splitTwo(rest, local, remote);
            cmd.putFile(local, remote);
        }
        else if (verb == "MODE" || verb == "mode")
        {
            if (rest.empty()) { std::cout << "Usage: MODE READONLY | READWRITE\n"; continue; }
            cmd.setMode(rest);
        }
        else
        {
            std::cout << "[ERROR] Unknown command. Use GET, PUT, MODE, or quit.\n";
        }
    }

    cmd.disconnect();
    std::cout << "[INFO] Goodbye.\n";
    return 0;
}
