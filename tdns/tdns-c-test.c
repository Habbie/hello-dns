#include "tdns-c.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{

  struct TDNSIPAddresses* ips;
  int err = TDNSLookupIPs("www.whitehouse.gov", 1000, 1, 1, &ips);
  if(err) {
    fprintf(stderr, "Error looking up domain name: %s", "error");
    return EXIT_FAILURE;
  }

  struct sockaddr_storage* res;
  for(int n = 0; ; ++n) {
    res = ips->addresses[n];
    printf("%p\n", res);
    if(!res)
      break;

    if(res->ss_family == AF_INET) {
      char ip[INET_ADDRSTRLEN];
      inet_ntop(res->ss_family, &((struct sockaddr_in*)res)->sin_addr, ip, INET_ADDRSTRLEN);
      printf("IPv4 address: %s\n", ip);
    }
  }
}
