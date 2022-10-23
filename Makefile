.PHONY = all clean
CXX = g++
CXXFLAGS = -Wall -pedantic -Wextra -g -std=c++11
TARGET=flow
LIBS=-lpcap
NAME=manual

all: $(TARGET)

$(TARGET): $(TARGET).cpp
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

doc: 
	pdflatex $(NAME).tex
	pdflatex $(NAME).tex


clean:
	rm -rf *.o $(TARGET) $(NAME).{aux,out,dvi,ps,log,te~,fls,toc,fdb_latexmk,synctex.gz}
