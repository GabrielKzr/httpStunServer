#include "include/StunServer.hpp"

#define CROW_MAIN

#define MAX_CLIENTS 1024

int main()
{
    StunServer stunServer(18080, MAX_CLIENTS);

    stunServer.stunServerInit();

    stunServer.stunServerClose();
}