CXXFLAGS:=-std=gnu++14 -Wall -O2 -MMD -MP -ggdb -Iext/simplesocket

PROGRAMS = tdns

all: $(PROGRAMS)

clean:
	rm -f *~ *.o *.d test $(PROGRAMS)

#check: mtests
#	./mtests

-include *.d

tdns: tdns.o ext/simplesocket/comboaddress.o ext/simplesocket/sclasses.o ext/simplesocket/swrappers.o
	g++ -std=gnu++14 $^ -o $@ 
