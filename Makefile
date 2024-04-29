all: aprs_analytics

aprs_analytics: aprs_analytics.c toml.c
	cc $^ -o $@ -lfap -lpq -I/usr/include/postgresql

clean :
	rm -f aprs_analytics

