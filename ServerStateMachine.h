#pragma once
#include <iostream>

enum ServerState
{
    DISCONNECTED,
    CONNECTED,
    AUTHENTICATED,
    PROCESSING
};

class ServerStateMachine
{
private:

    ServerState state;

public:

    ServerStateMachine()
    {
        state = DISCONNECTED;
    }

    void setState(ServerState s)
    {
        state = s;

        std::cout << "State -> " << state << std::endl;
    }

    ServerState getState()
    {
        return state;
    }
};
