#include "neighbor.h"

#include <cstdlib>
#include <cstring>
#include <iostream>

#include <linux/netlink.h>

#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <libnetlink.h>

#include "MacAddr.h"
#include "IPAddress.h"

int main(int argc, char* argv[])
{
    std::cout << "Starting" << std::endl;
    NetLink::NeighborList neighborListv4 = NetLink::getNeighborTable(AF_INET);
    NetLink::NeighborList neighborListv6 = NetLink::getNeighborTable(AF_INET6);
    for (NetLink::NeighborList::iterator iter=neighborListv4.begin();
         iter != neighborListv4.end();
         iter++) {
        std::cout << iter->ip.to_string() << " " << iter->device << " " << iter->mac.to_string() << " " << (iter->router ? "router" : "") << std::endl;
    }
    for (NetLink::NeighborList::iterator iter=neighborListv6.begin();
         iter != neighborListv6.end();
         iter++) {
        std::cout << iter->ip.to_string() << " " << iter->mac.to_string() << " " << (iter->router ? "router" : "") << std::endl;
    }

    std::cout << "Exiting" << std::endl;
    return 0;
}


namespace {

std::string index2name( int deviceIndex) {

    char buf[IF_NAMESIZE];
    char* result = if_indextoname(deviceIndex, buf);
    if (result == 0) {
        return "????";
    }
    return buf;
}

/**
 * parse the router attribute returned from netlink
 *
 * @param tb - table that will contain all the attributes fron the netlink router message
 * @param max - highest attrinute value to be parsed
 * @param rta - route attribute structure from the netlink message
 * @param len - length of the route attribute structure
 *
 */
void parseRouteAttribute(rtattr *routeAttrTable[], int max, rtattr *rta, int len)
{
    memset(routeAttrTable, 0, sizeof(rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
        if ((rta->rta_type <= max) && (!routeAttrTable[rta->rta_type]))
            routeAttrTable[rta->rta_type] = rta;
        rta = RTA_NEXT(rta,len);
    }
    if (len)
    {
        std::cout << "!!!Deficit parsing rt attribute " << len << " rta_len=" << rta->rta_len;
    }
}


/**
 * translates the netlink message into a NeighborEntry structure
 *
 * @param netlinkMessage
 * @param result - NeighborList that the new NewighborEntry will be pushed onto
 *
 * @return @li true - successfully created and added the entry
 *         @li false - the NeighborEntry could not be built correctly
 */
bool getNeighborEntry(nlmsghdr *netlinkMsgHdr, NetLink::NeighborList& result)
{
    NetLink::NeighborEntry entry;
    ndmsg *msgData = reinterpret_cast<ndmsg *>(NLMSG_DATA(netlinkMsgHdr));
    int family = msgData->ndm_family;

    int len = netlinkMsgHdr->nlmsg_len;
    rtattr * attrTable[NDA_MAX+1];

    if (netlinkMsgHdr->nlmsg_type != RTM_NEWNEIGH && netlinkMsgHdr->nlmsg_type != RTM_DELNEIGH) {
        return false;
    }
    len -= NLMSG_LENGTH(sizeof(*msgData));
    if (len < 0) {
        //BUG: wrong nlmsg len
        return false;
    }

    parseRouteAttribute(attrTable, NDA_MAX, NDA_RTA(msgData), netlinkMsgHdr->nlmsg_len - NLMSG_LENGTH(sizeof(*msgData)));

    if (attrTable[NDA_DST]) {
        if (family == AF_INET6) {
            IPv6Address ip(*reinterpret_cast<boost::asio::ip::address_v6::bytes_type*>(RTA_DATA(attrTable[NDA_DST])));
            entry.ip = ip;
        } else {
            IPv4Address ip(*reinterpret_cast<boost::asio::ip::address_v4::bytes_type*>(RTA_DATA(attrTable[NDA_DST])));
            entry.ip = ip;            
        }
        //std::cout << entry.ip.to_string() << std::endl;
    }

    int deviceIndex = msgData->ndm_ifindex;
    entry.device = index2name(deviceIndex);
    // std::cout << "dev " << ll_index_to_name(r->ndm_ifindex);

    if (attrTable[NDA_LLADDR]) {
        int macLen = RTA_PAYLOAD(attrTable[NDA_LLADDR]);
        if (macLen == 6) {
            MacAddr mac(reinterpret_cast<const u_int8_t*>(RTA_DATA(attrTable[NDA_LLADDR])));
            entry.mac = mac;
        } else {
            std::cout << "mac length is " << macLen << " for ip " << entry.ip.to_string() << ". Should be 6 for ethernet" << std::endl;
        }
    }

    if (msgData->ndm_flags & NTF_ROUTER) {
        entry.router=true;
    } else {
        entry.router = false;
    }
    
    if (msgData->ndm_state) {
        entry.nud = msgData->ndm_state;
    } else {
        entry.nud = 0;
    }
    
    result.push_back(entry);
    return 0;
}

} // end anonymous namespace


NetLink::NeighborList NetLink::getNeighborTable(int family) {
    NetLink::NeighborList result;

    struct RouteRequest {
        nlmsghdr n;
        ifaddrmsg r;
    };
    RouteRequest req;

    rtattr *routeAttr;
    int status;

    int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (fd < 0) {
        perror("Cannot open netlink socket");
        return result;
    }

    int sndbuf = 32768;
    if (setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf)) < 0) {
        perror("SO_SNDBUF");
        return result;
    }

    int rcvbuf = 1024 * 1024;
    if (setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&rcvbuf,sizeof(rcvbuf)) < 0) {
        perror("SO_RCVBUF");
        return result;
    }

     sockaddr_nl	local;
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    const unsigned int subscriptions = 0;
    local.nl_groups = subscriptions;

    if (bind(fd, ( sockaddr*)&local, sizeof(local)) < 0) {
        perror("Cannot bind netlink socket");
        return result;
    }

    socklen_t addr_len = sizeof(local);
    if (getsockname(fd, ( sockaddr*)&local, &addr_len) < 0) {
        perror("Cannot getsockname");
        return result;
    }
    if (addr_len != sizeof(local)) {
        fprintf(stderr, "Wrong address length %d\n", addr_len);
        return result;
    }
    if (local.nl_family != AF_NETLINK) {
        fprintf(stderr, "Wrong address family %d\n", local.nl_family);
	return result;
    }

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof( ifaddrmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
    req.n.nlmsg_type = RTM_GETNEIGH;
    
    
    /* AF_INET6 is used to signify the kernel to fetch only ipv6 entires.         *
     * Replacing this with AF_INET will fetch ipv4 address table.                 */    
    req.r.ifa_family = family;
    
    routeAttr = ( rtattr *)(((char *)&req) + NLMSG_ALIGN(req.n.nlmsg_len));
    if ( req.r.ifa_family == AF_INET6 ) {
        routeAttr->rta_len = RTA_LENGTH(16);
    } else {
        routeAttr->rta_len = RTA_LENGTH(4);
    }
    
    // send request for neighbor table
    status = send(fd, &req, req.n.nlmsg_len, 0);
    
    if (status < 0) {
        perror("send");
        return result;
    }

     sockaddr_nl nladdr;
     iovec iov;
     msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    char buf[16384];
    iov.iov_base = buf;

    status = recvmsg(fd, &msg, 0);
    if (status < 0) {
        std::cout << "netlink receive error " << strerror(errno) << " " << errno << std::endl;
        return result;
    }
    if (status == 0) {
        std::cout << "end of file on netlink" << std::endl;
        return result;
    }

     nlmsghdr *h = ( nlmsghdr*)buf;
    int msglen = status;
    while (NLMSG_OK(h, msglen)) {
        if (nladdr.nl_pid != 0 ||
            h->nlmsg_pid != local.nl_pid 
           ) {
            goto skip_it;
        }
        if (h->nlmsg_type == NLMSG_DONE) {
            break; /* process next filter */
        }
        if (h->nlmsg_type == NLMSG_ERROR) {
             nlmsgerr *err = ( nlmsgerr*)NLMSG_DATA(h);
            if (h->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr))) {
                std::cout << "ERROR truncated" << std::endl;
            } else {
                errno = -err->error;
                perror("RTNETLINK answers");
            }
            return result;
        }
        getNeighborEntry(h, result);
skip_it:
        h = NLMSG_NEXT(h, msglen);
    }
    
    return result;
}

