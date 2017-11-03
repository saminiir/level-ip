CPPFLAGS = -I include -Wall -Werror -pthread

src = $(wildcard src/*.c)
obj = $(patsubst src/%.c, build/%.o, $(src))
headers = $(wildcard include/*.h)
apps = apps/curl/curl

lvl-ip: $(obj)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(obj) -o lvl-ip
	@echo
	@echo "lvl-ip needs CAP_NET_ADMIN:"
	sudo setcap cap_setpcap,cap_net_admin=ep lvl-ip

build/%.o: src/%.c ${headers}
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

debug: CFLAGS+= -DDEBUG_SOCKET -DDEBUG_TCP -g -fsanitize=thread
debug: lvl-ip

apps: $(apps)
	$(MAKE) -C tools
	$(MAKE) -C apps/curl
	$(MAKE) -C apps/curl-poll

all: lvl-ip apps

test: debug apps
	@echo
	@echo "Networking capabilites are required for test dependencies:"
	which arping | sudo xargs setcap cap_net_raw=ep
	which tc | sudo xargs setcap cap_net_admin=ep
	@echo
	cd tests && ./test-run-all

clean:
	rm build/*.o lvl-ip
