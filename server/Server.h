//
// Created by Sergey Panov on 3/2/18.
//

#ifndef KRY_PROJECT_1_SERVER_H
#define KRY_PROJECT_1_SERVER_H


class Server {
private:
    const char* pipe;


public:
    const char& getPipe(){ return *pipe;}

    Server(const char* pipe): pipe{pipe}{}

    void communicate();


};


#endif //KRY_PROJECT_1_SERVER_H
