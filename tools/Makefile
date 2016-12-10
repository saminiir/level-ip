all: levelip liblevelip

levelip: levelip.c

liblevelip: liblevelip.c
	$(CC) -fPIC -shared -o liblevelip.so liblevelip.c -ldl

.PHONY:
clean:
	rm levelip.o liblevelip.so* levelip
