#ifndef NEIGHBOR_H
#define NEIGHBOR_H

#include "MacAddr.h"
#include "IPAddress.h"
#include <list>

namespace NetLink {

struct  NeighborEntry {
    IPAddress ip;
    MacAddr mac;
    int  nud;
    bool router;
    std::string device;
};

typedef std::list<NeighborEntry> NeighborList;


    NeighborList getNeighborTable(int family=AF_INET6);

};


#endif
