//
// Created by Sergey Panov on 3/2/18.
//

#include "Server.h"
#include <fcntl.h>
#include <iostream>
#include <unistd.h>

using namespace std;

void Server::communicate() {

    char sndMsg[100], recMsg[100];

    int fd;

    locale loc;
    while (true)
    {
        fd = open(pipe, O_RDONLY);  // Open pipe

        read(fd, recMsg, 100);

        cout << "Client sent: " << recMsg << endl;

        close(fd);

        fd = open(pipe, O_WRONLY);

        write(fd, recMsg, strlen(recMsg) + 1);

        close(fd);
    }

}
