PONGO_SRC ?= ../PongoOS
CC ?= xcrun -sdk iphoneos clang -arch arm64
CFLAGS +=  -I$(PONGO_SRC)/include -I$(PONGO_SRC)/src/kernel -I$(PONGO_SRC)/newlib/src/newlib/libc/include -Iinclude -I$(PONGO_SRC)/apple-include 
CFLAGS += -Wno-error=implicit-function-declaration

CFLAGS += -Os -ffreestanding -nostdlib -U__nonnull -DTARGET_OS_OSX=0 -DTARGET_OS_MACCATALYST=0 -D_GNU_SOURCE -DDER_TAG_SIZE=8
LDFLAGS += -Wl,-kext -Wl,-dead_strip -flto=thin -fno-stack-protector -L/opt/homebrew/Cellar/capstone/5.0.6/lib/ -lcapstone -static

all: kdemo

%.o: %.c
	$(CC) -c -nostdlib $(CFLAGS) $<

kdemo: main.o
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o kdemo

clean:
	rm -f kdemo *.o