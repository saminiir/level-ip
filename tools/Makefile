liblevelup: levelup.o
	$(CC) -shared -Wl,-soname,liblevelup.so.1 -o liblevelup.so.1.0.1 levelup.o -lc

levelup.o:
	$(CC) -fPIC -g -c -Wall levelup.c
