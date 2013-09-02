/* Use vanilla select()? */
//#define ASIO_USE_SELECT

/* Use poll()? */
//#define ASIO_USE_POLL

/* Use RTSIGs? (experimental, use at your own risk, works somewhat on Linux atleast) */
//#define ASIO_USE_RTSIG

/* Use epoll? (Works well (Linux >= 2.6), read README) */
#define ASIO_USE_EPOLL

/* Set non-blocking IO using FIONBIO (You will want to define this unless you have ASIO_USE_SIGIO) */
#define ASIO_USE_FIONBIO

#ifdef ASIO_USE_SELECT
#define ASIO_MAX_FDS FD_SETSIZE
#else
#define ASIO_MAX_FDS 131072
#endif

#define ASIO_R	0x1
#define ASIO_W	0x2

typedef unsigned int asio_event_type;

struct asio_event_entry_s
{
  asio_event_type event;
  int fd;
};

typedef struct asio_event_entry_s asio_event_entry;

struct asio_event_list_s
{
  unsigned int num_events;
  asio_event_entry events[ASIO_MAX_FDS];
};

typedef struct asio_event_list_s asio_event_list;

void asio_init(void);
int asio_add_fd(int, asio_event_type);
int asio_set_events(int, asio_event_type);
int asio_del_fd(int, asio_event_type);
asio_event_list *asio_wait_for_events(void);
