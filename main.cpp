#include <iostream>
#include <getopt.h>
#include <sys/stat.h>
#include "client/Client.h"
#include "server/Server.h"


#define PIPE "./fifo_pipe"

char getOption(int argc, char* argv[])
{
    int c;
    while ((c = getopt (argc, argv, "sc")) != -1)
    {
        switch (c)
        {
            case 'c':
                return 'c';
            case 's':
                return 's';
            case '?':
                std::cerr << "Unknown input parameter" << std::endl;
            default:
                exit(1);
        }
    }
    std::cerr << "Unknown input parameter" << std::endl;
    exit(1);
}

int main(int argc, char* argv[]) {

    int fd;
    const char* pipe = PIPE;    // Pipe pointer

    char param = getOption(argc, argv); // Parse input parameters

    fd = mkfifo(pipe, 0666);
    if (fd < 0)
    {
        std::cerr << "mkfifo() failed." << std::endl;
        std::cerr << errno << std::endl;

        if (errno == EEXIST)
        {
            std::cout << "Pipe already created" << std::endl;
        }
    }

    if (param == 'c')
    {
        std::cout << "I'm client" << std::endl;
        Client *client = new Client(pipe);
        client->communicate();
    }

    if (param == 's')
    {
        std::cout << "I'm server" << std::endl;
        Server *server = new Server(pipe);
        server->communicate();
    }


    return 0;
}