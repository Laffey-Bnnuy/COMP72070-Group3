#pragma once

#include <string>
#include "ClientStateMachine.h"

class SocketHandler;

class CommandProcessor
{
public:

    CommandProcessor(SocketHandler& socket);

    bool connectToServer(const std::string& host, int port);
    bool login(const std::string& username, const std::string& password);
    bool getFile(const std::string& remoteFilename, const std::string& localOutPath);
    bool putFile(const std::string& localPath, const std::string& remoteFilename);


    bool setMode(const std::string& modeName);

    void disconnect();

    const ClientStateMachine& getState() const { return state; }

private:

    SocketHandler& sock;
    ClientStateMachine state;
};
