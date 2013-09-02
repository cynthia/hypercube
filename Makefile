DEFS=-DUSE_LINUX_SENDFILE -DWITH_MYSQL
#DEFS=-DUSE_LINUX_SENDFILE
CC=gcc
CCFLAGS=$(DEFS) -Wall -ggdb
#CCFLAGS=$(DEFS) -Wall -Werror -ggdb #-pg
LDFLAGS=-ggdb #-pg
#LIBS=
LIBS=-L/usr/local/lib/mysql -lmysqlclient
AKEPOLLDEF=-DASIO_USE_AKEPOLL
AKEPOLLHDR=AKepoll.h
AKEPOLLOBJ=AKepoll.o
AKEPOLLDIR=asio/
OBJS=main.o akbuf/akbuf.o asio/asio.o $(AKEPOLLDIR)$(AKEPOLLOBJ) net.o log.o http.o cfg.o tracker.o

all: hypercube
clean:
	@rm *.o */*.o hypercube
setdist:
	./setdist.sh
dist.h: setdist
dist: setdist
	@rm -fr hypercube-dist
	@mkdir hypercube-dist hypercube-dist/akbuf hypercube-dist/asio
	cp README hypercube-dist/
	cp Makefile *.[ch] *.sh hypercube-dist/
	cp hypercube.cfg hypercube-dist/hypercube.cfg.dist
	cp tracker.cfg hypercube-dist/tracker.cfg.dist
	cp access.cfg hypercube-dist/access.cfg.dist
	mv hypercube-dist/config.h hypercube-dist/config.h.dist
	cp akbuf/Makefile akbuf/*.[ch] hypercube-dist/akbuf/
	cp asio/Makefile asio/*.[chs] hypercube-dist/asio/
	tar cvfz tracker-dist.tar.gz hypercube-dist/
	@cat dist.h|cut -d' ' -f3-
	@cat *.[ch] akbuf/*.[ch] asio/*.[chs] | wc -l
akbuf/akbuf.o: akbuf/akbuf.c akbuf/akbuf.h
	cd akbuf; make
asio/asio.o: asio/asio.c asio/asio.h
	cd asio;make AKEPOLLHDR=$(AKEPOLLHDR) AKEPOLLOBJ=$(AKEPOLLOBJ) AKEPOLLDEF=$(AKEPOLLDEF)
hypercube: $(OBJS)
	$(CC) $(LDFLAGS) -o hypercube $(OBJS) $(LIBS)
hypercube.h: config.h akbuf/akbuf.h asio/asio.h net.h http.h log.h cfg.h tracker.h
main.o: main.c hypercube.h config.h
	$(CC) $(CCFLAGS) -c main.c
net.o: net.c hypercube.h config.h
	$(CC) $(CCFLAGS) -c net.c
log.o: log.c hypercube.h config.h
	$(CC) $(CCFLAGS) -c log.c
http.o: http.c hypercube.h config.h
	$(CC) $(CCFLAGS) -c http.c
cfg.o: cfg.c hypercube.h config.h
	$(CC) $(CCFLAGS) -c cfg.c
tracker.o: tracker.c hypercube.h config.h tracker.h
	$(CC) $(CCFLAGS) -c tracker.c
