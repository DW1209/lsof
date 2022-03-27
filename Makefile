CXX = g++
CFLAGS = -Wall -g

PROGS = hw1

all: $(PROGS)

%: %.cpp
	$(CXX) -o $@ $(CFLAGS) $<

clean: 
	rm -f $(PROGS)
