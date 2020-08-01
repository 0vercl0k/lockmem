# Axel '0vercl0k' Souchet - March 8 2020
TARGET = lockmem.exe

SOURCES = \
    src\lockmem.cc \

CFLAGS = /O1 /nologo /ZI /W3 /D_AMD64_ /DWIN_X64 /sdl
LDFLAGS = /nologo /debug:full ntdll.lib

all: $(TARGET) clean

$(TARGET): $(SOURCES)
    if not exist bin mkdir bin
    cl $(CFLAGS) /Febin\$@ $** /link $(LDFLAGS)

clean:
    del *.obj *.pdb *.idb
    if exist .\bin del bin\*.exp bin\*.ilk bin\*.lib