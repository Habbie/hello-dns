CXXFLAGS:=-std=gnu++14 -Wall -O2 -MMD -MP -ggdb -Iext/simplesocket -Iext/catch -pthread

PROGRAMS = tdns tdig

all: $(PROGRAMS)

clean:
	rm -f *~ *.o *.d test $(PROGRAMS)

check: testrunner tdns tdig
	./testrunner
	cd tests ; ./basic

-include *.d

tdns: tdns.o record-types.o dns-storage.o dnsmessages.o contents.o ext/simplesocket/comboaddress.o ext/simplesocket/sclasses.o ext/simplesocket/swrappers.o
	g++ -std=gnu++14 $^ -o $@ -pthread

tdig: tdig.o record-types.o dns-storage.o dnsmessages.o ext/simplesocket/comboaddress.o ext/simplesocket/sclasses.o ext/simplesocket/swrappers.o
	g++ -std=gnu++14 $^ -o $@ -pthread


testrunner: tests.o record-types.o dns-storage.o dnsmessages.o 
	g++ -std=gnu++14 $^ -o $@ 
