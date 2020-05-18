#include <iostream>
#include "record-types.hh"
#include "dns-storage.hh"

using namespace std;

void launchDNSServer(vector<ComboAddress> locals);

int main(int argc, char** argv)
{
  if(argc < 2) {
    cerr<<"Syntax: tdns ipaddress:port [ipaddress:port] .. [[ipv6address]:port]] .."<<endl;
    return(EXIT_FAILURE);
  }

  vector<ComboAddress> locals;
  for(int n= 1; n < argc; ++n)
    locals.emplace_back(argv[n], 53);

  launchDNSServer(locals);
}
