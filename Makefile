CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDLIBS = -lssl -lcrypto

TARGET = sikradio
SRC = client.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDLIBS)

clean:
	rm -f $(TARGET) *.o