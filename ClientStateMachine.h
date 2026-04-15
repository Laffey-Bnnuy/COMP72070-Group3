#pragma once


enum ClientState
{
    IDLE,         
    CONNECTING,     
    AUTHENTICATING, 
    AUTHENTICATED,  
    TRANSFERRING,   
    DISCONNECTED    
};

class ClientStateMachine
{
    int state;

public:

    ClientStateMachine() : state(IDLE) {}

    void setState(int s) { state = s; }

    int  getState() const { return state; }


    const char* label() const
    {
        switch (state)
        {
        case IDLE:           return "IDLE";
        case CONNECTING:     return "CONNECTING";
        case AUTHENTICATING: return "AUTHENTICATING";
        case AUTHENTICATED:  return "AUTHENTICATED";
        case TRANSFERRING:   return "TRANSFERRING";
        case DISCONNECTED:   return "DISCONNECTED";
        default:             return "UNKNOWN";
        }
    }
};
