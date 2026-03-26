#pragma once

enum State
{
    DISCONNECTED,
    CONNECTED,
    AUTHENTICATED,
    PROCESSING
};

class ServerStateMachine
{
    int state;

public:

    void setState(int s)
    {
        state = s;
    }

    int getState()
    {
        return state;
    }
};
