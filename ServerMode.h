#pragma once


enum ServerMode
{
    MODE_READWRITE = 0,   // default: GET and PUT are both permitted
    MODE_READONLY  = 1    // only GET is permitted; PUT commands are rejected
};
