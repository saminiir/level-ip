CPPFLAGS = -I include -Wall

src = $(wildcard src/*.c)
obj = $(patsubst src/%.c, build/%.o, $(src))

lvl-ip: $(obj)
	$(CC) $(obj) -o lvl-ip

build/%.o: src/%.c
	$(CC) $(CPPFLAGS) -c $< -o $@

clean:
	rm build/*.o lvl-ip
