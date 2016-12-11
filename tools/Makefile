all: liblevelip

liblevelip: liblevelip.c
	$(CC) -fPIC -shared -o liblevelip.so liblevelip.c -ldl

.PHONY:
clean:
	rm liblevelip.so*
