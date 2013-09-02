int AKepoll_create(int);
int AKepoll_ctl(int, int, int, struct epoll_event *);
int AKepoll_wait(int, struct epoll_event *, int, int);
