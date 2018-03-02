//
// Created by Sergey Panov on 3/2/18.
//

#include <fcntl.h>
#include "Client.h"
#include <iostream>
#include <unistd.h>

using namespace std;


void Client::communicate() {

    char sndMsg[100], recMsg[100];

    int fd;

    locale loc;
    while (true)
    {
        fd = open(pipe, O_WRONLY);  // Open pipe

        cin >> sndMsg;

        write(fd, sndMsg, strlen(sndMsg) + 1);

        close(fd);

        fd = open(pipe, O_RDONLY);

        read(fd, recMsg, sizeof(recMsg));

        cout << "Server reply: " << recMsg << endl;

        if (  strcmp(recMsg, "BY") == 0 )
        {
            close(fd);
            break;
        }
    }

}
