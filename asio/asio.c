#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "asio.h"

#ifdef ASIO_USE_SELECT
#include <sys/select.h>
#endif
#ifdef ASIO_USE_EPOLL
#include <sys/epoll.h>
#endif
#ifdef ASIO_USE_POLL
#include <sys/poll.h>
#endif
#ifdef ASIO_USE_RTSIG
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <fcntl.h>
#include <signal.h>
#include <sys/poll.h>
#endif

#if !defined(ASIO_USE_SELECT) && !defined(ASIO_USE_EPOLL) && !defined(ASIO_USE_POLL) && !defined(ASIO_USE_RTSIG)
#error You must define one of ASIO_USE_SELECT, ASIO_USE_EPOLL, ASIO_USE_POLL, and ASIO_USE_RTSIG
#endif

#if defined(ASIO_USE_FIONBIO) && defined(ASIO_USE_RTSIG)
#error You cannot defined both ASIO_USE_FIONBIO and ASIO_USE_RTSIG
#endif

#ifndef MAX
#define MAX(a, b) (((a) > (b))? (a) : (b))
#endif
#ifndef MIN
#define MIN(a, b) (((a) < (b))? (a) : (b))
#endif

#ifdef ASIO_USE_SELECT
fd_set asio_rfds, asio_wfds;
int highest_rfd, highest_wfd;
#endif

#ifdef ASIO_USE_EPOLL
int epoll_fd;
#ifdef ASIO_USE_AKEPOLL
#include "AKepoll.h"
#else
#define AKepoll_create epoll_create
#define AKepoll_ctl epoll_ctl
#define AKepoll_wait epoll_wait
#endif
#endif

#ifdef ASIO_USE_POLL
  struct pollfd pollfds[ASIO_MAX_FDS];
  unsigned int num_pollfds;
#endif

void asio_init(void)
{
#ifdef ASIO_USE_RTSIG
  sigset_t sigs;
#endif

#ifdef ASIO_USE_SELECT
  FD_ZERO(&asio_rfds);
  FD_ZERO(&asio_wfds);
  highest_rfd = highest_wfd = -1;
#endif
#ifdef ASIO_USE_EPOLL
  if ((epoll_fd = AKepoll_create(ASIO_MAX_FDS)) == -1) { perror("epoll_create()"); exit(1); }
#endif
#ifdef ASIO_USE_POLL
  num_pollfds = 0;
#endif
#ifdef ASIO_USE_RTSIG
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGRTMIN + 1);
  sigprocmask(SIG_BLOCK, &sigs, NULL);
#endif
}
int asio_add_fd(int fd, asio_event_type events)
{
#ifdef ASIO_USE_EPOLL
  struct epoll_event ev;
#endif
#ifdef ASIO_USE_POLL
  unsigned int i;
#endif
#ifdef ASIO_USE_RTSIG
  int flags;
#endif
#ifdef ASIO_USE_FIONBIO
  int flags;
#endif
  if (fd < 0 || fd >= ASIO_MAX_FDS) return -1;
#ifdef ASIO_USE_SELECT
  if (events & ASIO_R)
  {
    FD_SET(fd, &asio_rfds);
    if (fd > highest_rfd) highest_rfd = fd;
  }
  if (events & ASIO_W)
  {
    FD_SET(fd, &asio_wfds);
    if (fd > highest_wfd) highest_wfd = fd;
  }
#endif
#ifdef ASIO_USE_EPOLL
  ev.data.fd = fd;
  ev.events = 0;
  if (events & ASIO_R) ev.events |= EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;
  if (events & ASIO_W) ev.events |= EPOLLOUT | EPOLLERR | EPOLLHUP;
  if (AKepoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) != 0) { perror("epoll_ctl()"); return -1; }
#endif
#ifdef ASIO_USE_POLL
  if (num_pollfds >= ASIO_MAX_FDS) return -1;
  for (i = 0; i < num_pollfds; i ++) if (pollfds[i].fd == fd || pollfds[i].events == 0) break;
  pollfds[i].fd = fd;
  pollfds[i].revents = 0;
  pollfds[i].events = 0;
  if (events & ASIO_R) pollfds[i].events |= POLLIN | POLLPRI | POLLERR | POLLHUP;
  if (events & ASIO_W) pollfds[i].events |= POLLOUT | POLLERR | POLLHUP;
  if (i == num_pollfds) num_pollfds ++; 
#endif
#ifdef ASIO_USE_RTSIG
  if ((flags = fcntl(fd, F_GETFL, 0)) < 0) { perror("fcntl() F_GETFL"); return -1; }
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK | O_ASYNC | O_RDWR) < 0) { perror("fcntl() F_SETFL"); return -1; }
  if (fcntl(fd, F_SETSIG, SIGRTMIN + 1) != 0) { perror("fcntl() F_SETSIG"); return -1; }
  if (fcntl(fd, F_SETOWN, getpid()) != 0) { perror("fcntl() F_SETOWN"); return -1; }
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK | O_ASYNC | O_RDWR) < 0) { perror("fcntl() F_SETFL 2"); return -1; }
#endif
#ifdef ASIO_USE_FIONBIO
  flags = 1;
  if (ioctl(fd, FIONBIO, &flags) != 0) { perror("ioctl()"); return -1; }
#endif
  return 0;
}
int asio_set_events(int fd, asio_event_type events)
{
#ifdef ASIO_USE_EPOLL
  struct epoll_event ev;
#endif
#ifdef ASIO_USE_POLL
  unsigned int i;
#endif

#ifdef ASIO_USE_SELECT
  return asio_add_fd(fd, events);
#endif
#ifdef ASIO_USE_EPOLL	
  ev.data.fd = fd;
  ev.events = 0;
  if (events & ASIO_R) ev.events |= EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP;
  if (events & ASIO_W) ev.events |= EPOLLOUT | EPOLLERR | EPOLLHUP;
  if (AKepoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) != 0) { perror("epoll_ctl()"); return -1; }
  return 0;
#endif
#ifdef ASIO_USE_POLL
  for (i = 0; i < num_pollfds; i ++) if (pollfds[i].fd == fd) break;
  if (i == num_pollfds) return -1;
  pollfds[i].events = 0;
  if (events & ASIO_R) pollfds[i].events |= POLLIN | POLLPRI | POLLERR | POLLHUP;
  if (events & ASIO_W) pollfds[i].events |= POLLOUT | POLLERR | POLLHUP;
  return 0;
#endif
#ifdef ASIO_USE_RTSIG
  return 0; /*XXX*/
#endif
}
int asio_del_fd(int fd, asio_event_type events)
{
#ifdef ASIO_USE_EPOLL
  struct epoll_event ev;
#endif
#ifdef ASIO_USE_POLL
  unsigned int i;
#endif 

  if (fd < 0 || fd >= ASIO_MAX_FDS) return -1;
#ifdef ASIO_USE_SELECT
  if (FD_ISSET(fd, &asio_rfds) && fd == highest_rfd) highest_rfd --;
  FD_CLR(fd, &asio_rfds);
  if (FD_ISSET(fd, &asio_wfds) && fd == highest_wfd) highest_wfd --;
  FD_CLR(fd, &asio_wfds);
#endif
#ifdef ASIO_USE_EPOLL
  ev.data.fd = fd;
  ev.events = 0;
  if (events & ASIO_R) ev.events |= EPOLLIN | EPOLLPRI;
  if (events & ASIO_W) ev.events |= EPOLLOUT;
  AKepoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ev);
#endif
#ifdef ASIO_USE_POLL
  for (i = 0; i < num_pollfds; i ++) if (pollfds[i].fd == fd) break;
  if (i == num_pollfds) return - 1;
  pollfds[i].fd = -1;
  pollfds[i].events = 0;
  if (num_pollfds - 1 == i) num_pollfds --;
#endif
  return 0;  
}

asio_event_list *asio_wait_for_events(void)
{
  static asio_event_list ret;
#ifdef ASIO_USE_SELECT
  fd_set event_rfds, event_wfds;
  struct timeval tv;
  int i;
#endif
#ifdef ASIO_USE_EPOLL
  struct epoll_event epoll_events[ASIO_MAX_FDS];
  int i, j;
#endif
#ifdef ASIO_USE_POLL
  int i, j;
#endif
#ifdef ASIO_USE_RTSIG
  sigset_t sigs;
  siginfo_t sigi;
  struct timespec ts;
  int sig;
#endif
  
  ret.num_events = 0;
#ifdef ASIO_USE_SELECT
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  event_rfds = asio_rfds;
  event_wfds = asio_wfds;
  if (select(MAX(highest_rfd, highest_wfd) + 1, &event_rfds, &event_wfds, NULL, &tv) > 0)
  {
    for (i = 0; i <= highest_rfd; i ++) if (FD_ISSET(i, &event_rfds))
    {
      assert(ret.num_events < ASIO_MAX_FDS);
      ret.events[ret.num_events].event = ASIO_R;
      ret.events[ret.num_events].fd = i;
      ret.num_events ++;
    }
    for (i = 0; i <= highest_wfd; i ++) if (FD_ISSET(i, &event_wfds))
    {
      assert(ret.num_events < ASIO_MAX_FDS);
      ret.events[ret.num_events].event = ASIO_W;
      ret.events[ret.num_events].fd = i;
      ret.num_events ++;
    }
  }   
#endif
#ifdef ASIO_USE_EPOLL
  if ((j = AKepoll_wait(epoll_fd, epoll_events, ASIO_MAX_FDS, 1000)) < 0)
  {
    return &ret; /*XXX*/
  }
  if (j > 0)
  {
    for (i = 0; i < j; i ++)
    {
      if (epoll_events[i].events & (EPOLLERR | EPOLLHUP))
      {
        assert(ret.num_events < ASIO_MAX_FDS);
        ret.events[ret.num_events].event = ASIO_R | ASIO_W;
        ret.events[ret.num_events].fd = epoll_events[i].data.fd;
        ret.num_events ++;
      } else
      {
        if (epoll_events[i].events & (EPOLLIN | EPOLLPRI))
        {
          assert(ret.num_events < ASIO_MAX_FDS);
          ret.events[ret.num_events].event = ASIO_R;
          ret.events[ret.num_events].fd = epoll_events[i].data.fd;
          ret.num_events ++;
        }
        if (epoll_events[i].events & EPOLLOUT)
        {
          assert(ret.num_events < ASIO_MAX_FDS);
          ret.events[ret.num_events].event = ASIO_W;
          ret.events[ret.num_events].fd = epoll_events[i].data.fd;
          ret.num_events ++;
        }  
      }    
    }
  }
#endif
#ifdef ASIO_USE_POLL
  if ((j = poll(pollfds, num_pollfds, 1000)) < 0)
  {
    if (errno == EINTR || errno == EAGAIN) return &ret;
    perror("poll()"); return NULL;
  }
  for (i = 0; i < num_pollfds; i ++)
  {
    if (pollfds[i].revents & (POLLERR | POLLHUP) && pollfds[i].events & (POLLIN | POLLOUT))
    {
      assert(ret.num_events < ASIO_MAX_FDS);
      ret.events[ret.num_events].fd = pollfds[i].fd;
      ret.events[ret.num_events].event = 0;
      if (pollfds[i].events & POLLIN) ret.events[ret.num_events].event |= ASIO_R;
      if (pollfds[i].events & POLLOUT) ret.events[ret.num_events].event |= ASIO_W;
      ret.num_events ++;
    } else
    {
      if (pollfds[i].revents & (POLLIN | POLLPRI))
      {
        assert(ret.num_events < ASIO_MAX_FDS);
        ret.events[ret.num_events].event = ASIO_R;
        ret.events[ret.num_events].fd = pollfds[i].fd;
        ret.num_events ++;
      }
      if (pollfds[i].revents & POLLOUT)
      {
        assert(ret.num_events < ASIO_MAX_FDS);
        ret.events[ret.num_events].event = ASIO_W;
        ret.events[ret.num_events].fd = pollfds[i].fd;
        ret.num_events ++;
      }
    }
  }
#endif
#ifdef ASIO_USE_RTSIG
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGRTMIN + 1);
  memset(&sigi, 0, sizeof(sigi));
  ts.tv_sec = 1;
  ts.tv_nsec = 0;
  if ((sig = sigtimedwait(&sigs, &sigi, &ts)) == SIGRTMIN + 1)
  {
    //if (sigi.si_band & POLLIN) printf("fd %d event IN\n", sigi.si_fd);
    //if (sigi.si_band & POLLOUT) printf("fd %d event OUT\n", sigi.si_fd);
    assert(ret.num_events < ASIO_MAX_FDS);
    ret.events[ret.num_events].fd = sigi.si_fd; 
    ret.events[ret.num_events].event = 0;
    if (sigi.si_band & POLLIN) ret.events[ret.num_events].event |= ASIO_R;
    if (sigi.si_band & POLLOUT) ret.events[ret.num_events].event |= ASIO_W;
    if (sigi.si_band & (POLLERR | POLLHUP)) ret.events[ret.num_events].event |= ASIO_R | ASIO_W; /*XXX*/
    ret.num_events ++;
  }
#endif
  return &ret;  
}
