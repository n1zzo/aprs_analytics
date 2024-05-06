# CFLAGS:= -g -O0 -fsanitize=address

all: aprs_analytics

aprs_analytics: aprs_analytics.c toml.c
	cc $^ -o $@ $(CFLAGS)  -lfap -lpq -I/usr/include/postgresql

clean :
	rm -f aprs_analytics

