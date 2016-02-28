CPPFLAGS = -I include -Wall

src = $(wildcard src/*.c)
obj = $(patsubst src/%.c, build/%.o, $(src))

lvl-ip: $(obj)
	$(CC) $(obj) -o lvl-ip

build/%.o: src/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm build/*.o lvl-ip
