.PHONY = all clean
CXX = g++
CXXFLAGS = -Wall -pedantic -Wextra -g -std=c++11
TARGET=flow
LIBS=-lpcap

all: $(TARGET)

$(TARGET): $(TARGET).cpp
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -rf *.o $(TARGET) 