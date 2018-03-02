//
// Created by Sergey Panov on 3/2/18.
//

#ifndef KRY_PROJECT_1_CLIENT_H
#define KRY_PROJECT_1_CLIENT_H


class Client {

private:
    const char* pipe;


public:
    const char& getPipe(){ return *pipe;}

    Client(const char* pipe): pipe{pipe}{}

    void communicate();

};


#endif //KRY_PROJECT_1_CLIENT_H
