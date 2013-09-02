#define NET_FD_INIT_TYPE		NET_FD_READLINE
#define net_fd_init_data_callback	http_handle_action_and_headers
#define net_fd_init_sent_callback	http_handle_sent
#define net_unset_fd_callback		http_unset_fd

#define FD_VALID(fd) ((unsigned int)(fd) < ASIO_MAX_FDS)

enum { NET_FD_UNUSED, NET_FD_LISTEN, NET_FD_READ, NET_FD_READLINE, NET_FD_SEND, NET_FD_RAW };
typedef unsigned int net_fd_type;

struct net_fd_entry_s
{
  net_fd_type type;
  void (*data_callback)();
  void (*sent_callback)();
  time_t active_time;
  akbuf_ctxh ctx;
  akbuf *peerbuf;
  akbuf *sockbuf;
  akbuf *readbuf, *linebuf;
  akbuf *sendbuf;
  int send_fd;
  AKsize_t send_fd_len;
  off_t send_fd_off;
};

typedef struct net_fd_entry_s net_fd_entry;

void net_init(void);
void net_start_listen(void);
void net_set_fd(int, net_fd_type, void (*)(), void (*)(), unsigned int);
void net_set_callbacks(int, void (*)(), void (*)());
void net_set_type(int, net_fd_type);
void net_send_buf(int, akbuf *);
void net_unset_fd(int);
void net_send(int);
void net_wait_for_events(void);
void net_periodic(void);
