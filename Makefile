CXX = g++
CFLAGS = -Wall -g

PROGS = lsof

all: $(PROGS)

%: %.cpp
	$(CXX) -o $@ $(CFLAGS) $<

clean: 
	rm -f $(PROGS)
