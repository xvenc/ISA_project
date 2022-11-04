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

archive:
	tar -cvf xkorva03.tar $(NAME).pdf Makefile $(TARGET).{cpp,1} README.md

clean:
	rm -rf *.o $(TARGET) $(NAME).{aux,out,dvi,ps,log,te~,fls,toc,fdb_latexmk,synctex.gz}
