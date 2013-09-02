enum { HTTP_FD_UNUSED, HTTP_FD_NEW_REQ, HTTP_FD_ACTION, HTTP_FD_HEADERS, HTTP_FD_CONTENT, HTTP_FD_PIPING, HTTP_FD_CGI, HTTP_FD_DIR };
enum { HTTP_METHOD_NONE, HTTP_METHOD_GET, HTTP_METHOD_HEAD, HTTP_METHOD_POST };

#define HTTP_OK			200
#define HTTP_PARTIAL_CONTENT	206
#define HTTP_MOVED_PERM		301
#define HTTP_BAD_REQUEST	400
#define HTTP_FORBIDDEN		403
#define HTTP_NOT_FOUND		404
#define HTTP_INTERNAL_ERROR	500
#define HTTP_SERVER_TOO_BUSY	503
#define HTTP_FORBIDDEN_BANNED	2403

#define HTTP_LOG_HOOK		1000

typedef unsigned int http_fd_state;

struct http_fd_entry_s
{
  http_fd_state state;
  akbuf_ctxh ctx;
  unsigned int method;
  akbuf *uri;
  akbuf *query;
  akbuf *content;
  unsigned int num_args;
  akbuf_table *args;
  AKsize_t content_len;
  unsigned int ver_maj, ver_min;
  unsigned int keep_alive;
  unsigned int num_headers;
  akbuf_table *headers;
  int rpipe_fd;
  net_fd_entry *rpipe_net_ent;
  int wpipe_fd;
  net_fd_entry *wpipe_net_ent;
  DIR *listdir;
  akbuf *dirpath;
};

typedef struct http_fd_entry_s http_fd_entry;

void http_init(void);
void http_unset_fd(int);
void http_handle_sent(int, net_fd_entry *);
unsigned char *http_status_msg(unsigned int);
void http_handle_action_and_headers(int, net_fd_entry *, akbuf *);
