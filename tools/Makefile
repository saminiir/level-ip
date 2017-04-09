CPPFLAGS = -I ../include

all: liblevelip

liblevelip: liblevelip.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -fPIC -shared -o liblevelip.so liblevelip.c -ldl

.PHONY:
clean:
	rm liblevelip.so*
