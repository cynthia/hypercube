#include "hypercube.h"

net_fd_entry net_fds[ASIO_MAX_FDS];

extern hypercube_config cfg;

time_t period_time;

void net_init(void)
{
  unsigned int i;
  
  period_time = time(NULL);
  for (i = 0; i < ASIO_MAX_FDS; i ++) net_fds[i].type = NET_FD_UNUSED;
  asio_init();
  DEBUGF("network initialized");
}
void net_set_fd(int fd, net_fd_type type, void (*data_callback)(), void (*sent_callback)(), unsigned int alloc_buf)
{
  AKassert(FD_VALID(fd));
  net_fds[fd].type = type;
  net_fds[fd].data_callback = data_callback;
  net_fds[fd].sent_callback = sent_callback;
  net_fds[fd].active_time = time(NULL);
  net_fds[fd].ctx = akbuf_new_ctx();
  if (alloc_buf == 1)
  {
    net_fds[fd].readbuf = akbuf_init(net_fds[fd].ctx, 0);
    net_fds[fd].linebuf = akbuf_init(net_fds[fd].ctx, 0);
    net_fds[fd].sendbuf = akbuf_init(net_fds[fd].ctx, 0);
    net_fds[fd].peerbuf = akbuf_init(net_fds[fd].ctx, 0);
    net_fds[fd].sockbuf = akbuf_init(net_fds[fd].ctx, 0);
  } else
  {
    net_fds[fd].readbuf = net_fds[fd].linebuf = net_fds[fd].sendbuf = net_fds[fd].peerbuf = net_fds[fd].sockbuf = NULL;
  }
  net_fds[fd].send_fd = -1;
  switch (type)
  {
    case NET_FD_LISTEN: case NET_FD_READ: case NET_FD_READLINE: case NET_FD_RAW:
      if (asio_add_fd(fd, ASIO_R) != 0) { akperror("asio_add_fd()"); exit(1); }
      break;
    case NET_FD_SEND:
      if (asio_add_fd(fd, ASIO_W) != 0) { akperror("asio_add_fd()"); exit(1); }
      break;
  }
}
void net_set_callbacks(int fd, void (*data_callback)(), void (*sent_callback)())
{
  AKassert(FD_VALID(fd));
  net_fds[fd].data_callback = data_callback;
  net_fds[fd].sent_callback = sent_callback;
}
void net_set_type(int fd, net_fd_type type)
{
  AKassert(FD_VALID(fd));
  net_fds[fd].type = type;
}
void net_send_buf(int fd, akbuf *buf)
{
  AKassert(FD_VALID(fd));
  akbuf_append_buf(net_fds[fd].sendbuf, buf);
}
void net_unset_fd(int fd)
{
  AKassert(FD_VALID(fd));
  DEBUGF("unsetting fd %d", fd);
  net_unset_fd_callback(fd);
  if (net_fds[fd].type != NET_FD_UNUSED)
  {
    akbuf_free_ctx(net_fds[fd].ctx);
    net_fds[fd].ctx = (akbuf_ctxh)0;
    if (net_fds[fd].send_fd != -1) close(net_fds[fd].send_fd);
    net_fds[fd].type = NET_FD_UNUSED;
  }
  asio_del_fd(fd, ASIO_R | ASIO_W);
  close(fd);
}
void net_start_listen(void)
{
  int sock;
  unsigned int i;
  struct sockaddr_in sin;
    
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0 || sock >= ASIO_MAX_FDS) { akperror("socket()"); exit(1); }
  i = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&i, sizeof(i)) != 0) { akperror("setsockopt()"); exit(1); }
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = cfg.listen_addr.s_addr;
  sin.sin_port = htons(cfg.listen_port);
  if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) != 0) { akperror("bind()"); exit(1); }
  if (listen(sock, LISTEN_BACKLOG) != 0) { akperror("listen() (decrease LISTEN_BACKLOG?)"); exit(1); }
  net_set_fd(sock, NET_FD_LISTEN, NULL, NULL, 0);
  aklogf(LOG_INFO, "Listening on port %d.", cfg.listen_port);
}
void test_readline(int fd, net_fd_entry *net_ent, akbuf *line)
{
  akbuf_asciiz(line);
  printf("TEST: readline [%s]\n", akbuf_data(line));
}
void net_accept_connection(int fd)
{
  struct sockaddr_in sin;
  size_t sin_len;
  int newfd;
  
  sin_len = sizeof(sin);
  memset(&sin, 0, sizeof(sin));
  if ((newfd = accept(fd, (struct sockaddr *)&sin, &sin_len)) < 0) { akperror("accept()"); return; }
  if (!FD_VALID(newfd))
  {
    aklogf(LOG_INFO, "Client limit reached. Increase ASIO_MAX_FDS?");
    close(newfd);
    return;
  }
  net_set_fd(newfd, NET_FD_INIT_TYPE, net_fd_init_data_callback, net_fd_init_sent_callback, 1);
  akbuf_sprintf(net_fds[newfd].peerbuf, "%s:%u", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
  sin_len = sizeof(sin);
  memset(&sin, 0, sizeof(sin));
  if (getsockname(newfd, (struct sockaddr *)&sin, &sin_len) == 0)
  {
    akbuf_sprintf(net_fds[newfd].sockbuf, "%s:%u", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
  } else
  {
    akbuf_strcpy(net_fds[newfd].sockbuf, "");
  }
  aklogf(LOG_CONNECTION, "%d: Connection from %s", newfd, akbuf_data(net_fds[newfd].peerbuf));
}
void net_send(int fd)
{
  DEBUGF("send on fd %d", fd);
  asio_set_events(fd, ASIO_W);
  net_fds[fd].type = NET_FD_SEND;
}
void net_sent(int fd)
{
  DEBUGF("sent on fd %d", fd);
  asio_set_events(fd, ASIO_R);
  net_fds[fd].type = NET_FD_INIT_TYPE;
  if (net_fds[fd].send_fd != -1) { close(net_fds[fd].send_fd); net_fds[fd].send_fd = -1; }
  if (net_fds[fd].sent_callback != NULL) net_fds[fd].sent_callback(fd, &net_fds[fd]);
}
void net_handle_send(int fd)
{
  AKssize_t n, m;
  
  if (!akbuf_empty(net_fds[fd].sendbuf))
  {
    if ((n = write(fd, akbuf_data(net_fds[fd].sendbuf), akbuf_idx(net_fds[fd].sendbuf))) <= 0)
    {
      if (errno != EINTR && errno != EAGAIN) net_unset_fd(fd);
      return;
    }
    akbuf_consume(net_fds[fd].sendbuf, n);
    if (akbuf_empty(net_fds[fd].sendbuf) && net_fds[fd].send_fd == -1)
    {
      net_sent(fd);
      return;
    }
  } else if (net_fds[fd].send_fd != -1)
  {
#ifdef USE_LINUX_SENDFILE  
    if ((m = sendfile(fd, net_fds[fd].send_fd, &net_fds[fd].send_fd_off, (net_fds[fd].send_fd_len >= SEND_BUF_SIZE)? SEND_BUF_SIZE : net_fds[fd].send_fd_len)) < 0)
    {
      if (errno != EAGAIN && errno != EINTR) { akperror("sendfile()"); net_unset_fd(fd); }
      return;
    }
    net_fds[fd].send_fd_len -= m;
    if (net_fds[fd].send_fd_len == 0) net_sent(fd);
#else
    unsigned char readbuf[SEND_BUF_SIZE];
    
    if (net_fds[fd].send_fd_off != 0)
    {
      if (lseek(fd, net_fds[fd].send_fd_off, SEEK_SET) == (off_t)-1) akperror("lseek()"); 
      net_fds[fd].send_fd_off = 0;
    }
    if ((n = read(net_fds[fd].send_fd, readbuf, sizeof(readbuf))) <= 0)
    {
      if (errno != EINTR && errno != EAGAIN) net_sent(fd);
      return;
    }
    if ((m = write(fd, readbuf, n)) <= 0)
    {
      if (errno != EINTR && errno != EAGAIN) net_unset_fd(fd);
      return;
    }
    if (m < n) akbuf_append_data(net_fds[fd].sendbuf, &readbuf[m], n - m);
#endif
  } else
  {
    net_sent(fd);
  }
}
void net_handle_readline(int fd)
{
  AKssize_t n;
  unsigned char readbuf[BUF_SIZE];
  int i, j;
  
  if ((n = read(fd, readbuf, sizeof(readbuf))) <= 0)
  {
    if (errno != EINTR && errno != EAGAIN) net_unset_fd(fd);
    return;
  }
  DEBUGF("read %d bytes", n);
  akbuf_append_data(net_fds[fd].readbuf, readbuf, n);
  if (akbuf_idx(net_fds[fd].readbuf) > MAX_LINE_LEN)
  {
    net_unset_fd(fd);
    return;
  }
  while ((i = akbuf_chr(net_fds[fd].readbuf, '\n')) >= 0 && net_fds[fd].type == NET_FD_READLINE)
  {
    akbuf_split(net_fds[fd].readbuf, net_fds[fd].linebuf, i);
    if ((j = akbuf_chr(net_fds[fd].linebuf, '\r')) >= 0) akbuf_set_idx(net_fds[fd].linebuf, j);
    if (net_fds[fd].data_callback != NULL) net_fds[fd].data_callback(fd, &net_fds[fd], net_fds[fd].linebuf);
  }
  if (net_fds[fd].type == NET_FD_READ && akbuf_idx(net_fds[fd].readbuf) > 0)
  {
    /* State changed with data remaining in buffer, so handle it. */
    if (net_fds[fd].data_callback != NULL) net_fds[fd].data_callback(fd, &net_fds[fd], net_fds[fd].readbuf);
    akbuf_set_idx(net_fds[fd].readbuf, 0);
  }
}
void net_handle_read(int fd)
{
  AKssize_t n;
  unsigned char readbuf[BUF_SIZE];
  
  if ((n = read(fd, readbuf, sizeof(readbuf))) <= 0)
  {
    if (errno != EINTR && errno != EAGAIN) net_unset_fd(fd);
    return;
  }
  DEBUGF("read %d bytes", n);
  akbuf_set_data(net_fds[fd].readbuf, readbuf, n);
  if (net_fds[fd].data_callback != NULL) net_fds[fd].data_callback(fd, &net_fds[fd], net_fds[fd].readbuf);
}
void net_handle_raw(int fd)
{
  DEBUGF("raw event on fd %d", fd);
  if (net_fds[fd].data_callback != NULL) net_fds[fd].data_callback(fd, &net_fds[fd], NULL);
}
void net_wait_for_events(void)
{
  asio_event_list *evs;
  unsigned int i;
  int fd;
  
  evs = asio_wait_for_events();
  AKassert(evs != NULL);
  //DEBUGF("got %u events", evs->num_events);
  for (i = 0; i < evs->num_events; i ++)
  {
    fd = evs->events[i].fd;
    AKassert(FD_VALID(fd));
    DEBUGF("event on fd %d", fd);
    net_fds[fd].active_time = time(NULL);
    if (evs->events[i].event & ASIO_R)
    {
      switch (net_fds[fd].type)
      {
        case NET_FD_LISTEN: net_accept_connection(fd); break;
        case NET_FD_READLINE: net_handle_readline(fd); break;
        case NET_FD_READ: net_handle_read(fd); break;
        case NET_FD_RAW: net_handle_raw(fd); break;
        default: DEBUGF("Unknown revent type %u on fd %d", net_fds[fd].type, fd);
      }
    }
    if (evs->events[i].event & ASIO_W)
    {
      switch (net_fds[fd].type)
      {
        case NET_FD_SEND: net_handle_send(fd); break;
        default: DEBUGF("Unknown wevent type %u on fd %d", net_fds[fd].type, fd);
      }
    }
  }
}
void net_periodic(void)
{
#ifdef SOCKET_TIMEOUT
  unsigned int i;
  time_t t;

  if (time(NULL) - period_time >= SOCKET_TIMEOUT / 2)
  {
    t = time(NULL);
    for (i = 0; i < ASIO_MAX_FDS; i ++) if (net_fds[i].type != NET_FD_UNUSED && net_fds[i].type != NET_FD_LISTEN && net_fds[i].type != NET_FD_RAW && t - net_fds[i].active_time >= SOCKET_TIMEOUT)
    {
      net_unset_fd(i);
    }
    period_time = time(NULL);
  }
#endif
}
