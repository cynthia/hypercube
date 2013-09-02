#include "hypercube.h"

http_fd_entry http_fds[ASIO_MAX_FDS];

static akbuf_ctxh http_ctx;
static akbuf *parsebufs[8];

extern hypercube_config cfg;

void http_init(void)
{
  unsigned int i;
  
  http_ctx = akbuf_new_ctx();
  for (i = 0; i < sizeof(parsebufs) / sizeof(parsebufs[0]); i ++) parsebufs[i] = akbuf_init(http_ctx, 0);
  for (i = 0; i < ASIO_MAX_FDS; i ++) http_fds[i].state = HTTP_FD_UNUSED;
}
void http_unset_fd(int fd)
{
  if (http_fds[fd].state != HTTP_FD_UNUSED)
  {
    if (http_fds[fd].state != HTTP_FD_CGI) aklogf(LOG_CONNECTION, "Client on socket %d disconnected.", fd);
    http_fds[fd].state = HTTP_FD_UNUSED;
  }
}
void http_handle_sent(int fd, net_fd_entry *net_ent)
{
  DEBUGF("send on socket %d done", fd);
  if (http_fds[fd].keep_alive == 0)
  {
    net_unset_fd(fd);
  } else
  {
    http_fds[fd].state = HTTP_FD_NEW_REQ;
  }
}
unsigned char *http_status_msg(unsigned int code)
{
  switch (code)
  {
    case HTTP_OK: return "OK";
    case HTTP_PARTIAL_CONTENT: return "Partial content";
    case HTTP_MOVED_PERM: return "Moved permanently";
    case HTTP_BAD_REQUEST: return "Bad request";
    case HTTP_FORBIDDEN: return "Forbidden";
    case HTTP_NOT_FOUND: return "Not found";
    case HTTP_INTERNAL_ERROR: return "Internal error";
    case HTTP_SERVER_TOO_BUSY: return "Server too busy";
    case HTTP_LOG_HOOK: return "Handled by hook";
    case HTTP_FORBIDDEN_BANNED: return "Forbidden (client banned)";
  }
  return "Unspecified";
}
unsigned char *http_method_str(unsigned int method)
{
  switch (method)
  {
    case HTTP_METHOD_GET: return "GET"; 
    case HTTP_METHOD_HEAD: return "HEAD"; 
    case HTTP_METHOD_POST: return "POST";
  }
  return "(none)";
}
void http_log_query(int fd, net_fd_entry *net_ent, unsigned int code)
{
  unsigned char *ua_p, *ref_p, *host_p;

  if ((host_p = akbuf_table_entry_get_str(http_fds[fd].headers, "Host")) == NULL) host_p = "(none)";
  if ((ua_p = akbuf_table_entry_get_str(http_fds[fd].headers, "User-agent")) == NULL) ua_p = "(none)";
  if ((ref_p = akbuf_table_entry_get_str(http_fds[fd].headers, "Referer")) == NULL) ref_p = "(none)";
  akbuf_asciiz(net_ent->peerbuf);
  akbuf_asciiz(http_fds[fd].uri);
  aklogf(LOG_REQUEST, "HTTP/%u.%u %d %s %s \"%s\" %u \"%s\" \"%s\" \"%s\" \"%s\"", 
    http_fds[fd].ver_maj, http_fds[fd].ver_min,
    fd,
    akbuf_data(net_ent->peerbuf),
    http_method_str(http_fds[fd].method), akbuf_data(http_fds[fd].uri),
    (code == HTTP_LOG_HOOK)? HTTP_OK : code, http_status_msg(code),
    host_p, ref_p, ua_p);
}
void http_error(int fd, net_fd_entry *net_ent, unsigned int code)
{
  unsigned char *msg;
  
  http_log_query(fd, net_ent, code);
  msg = http_status_msg(code);
  if (code >= 2000) code -= 2000;
  http_fds[fd].keep_alive = 0;
  akbuf_sprintf(net_ent->sendbuf,
    "HTTP/1.1 %u %s\r\n"
    "Server: " SERVER_VERSION "\r\n"
    "Content-type: text/html\r\n"
    "Connection: close\r\n"
    "\r\n"
    "<HTML><HEAD><TITLE>%u %s</TITLE></HEAD><BODY><H3>%u %s</H3></BODY></HTML>\r\n",
    code, msg,
    code, msg, code, msg);
  net_send(fd);
}
unsigned char *get_mime_type(unsigned char *filename)
{
  unsigned int i;
  unsigned char *p;
      
  i = strlen(filename);
  while (i >= 1) { if (filename[i - 1] == '.') break; i --; }
  if (i > 0)
  {
    DEBUGF("get_mime_type() extension %s", &filename[i]);
    if ((p = akbuf_table_entry_get_str(cfg.mime_types, &filename[i])) != NULL) return p;
  }
  return "application/octet-stream";
}
void cgi_handle_output(int fd, net_fd_entry *net_ent, akbuf *buf)
{
  if (http_fds[fd].rpipe_net_ent->type == HTTP_FD_UNUSED)
  {
    net_unset_fd(fd);
    return;
  }
  akbuf_append_buf(http_fds[fd].rpipe_net_ent->sendbuf, buf);
  net_send(http_fds[fd].rpipe_fd);
}
void cgi_handle_sent_content(int fd, net_fd_entry *net_ent, akbuf *buf)
{
  net_unset_fd(fd);
}
int serve_cgi_to_fd(int fd, net_fd_entry *net_ent, unsigned char *cgi_name)
{
  int cgi_rpipe[2], cgi_wpipe[2];
  /* parsebufs: 0,1,2 == env var tmp */
  unsigned int has_content;
  
  DEBUGF("serving cgi [%s]", cgi_name);
  cgi_rpipe[0] = cgi_rpipe[1] = -1;
  if (pipe(cgi_rpipe) != 0 || !FD_VALID(cgi_rpipe[0]) || !FD_VALID(cgi_rpipe[1]))
  {
    if (cgi_rpipe[0] != -1) close(cgi_rpipe[0]);
    if (cgi_rpipe[1] != -1) close(cgi_rpipe[1]);
    http_error(fd, net_ent, HTTP_SERVER_TOO_BUSY);
    return -2;
  }
  if (http_fds[fd].method == HTTP_METHOD_POST && http_fds[fd].content_len > 0)
  {
    has_content = 1;
    cgi_wpipe[0] = cgi_wpipe[1] = -1;
    if (pipe(cgi_wpipe) != 0 || !FD_VALID(cgi_wpipe[0]) || !FD_VALID(cgi_wpipe[1]))
    {
      if (cgi_wpipe[0] != -1) close(cgi_wpipe[0]);
      if (cgi_wpipe[1] != -1) close(cgi_wpipe[1]);
      http_error(fd, net_ent, HTTP_SERVER_TOO_BUSY);
      return -2;
    }
  } else
  {
    has_content = 0;
  }
  if (fork() == 0)
  {
    unsigned char *envs[64];
    unsigned int i;
    int j;
    
    if (has_content == 1)
    {
      close(cgi_wpipe[1]);
      dup2(cgi_wpipe[0], 0);
    }
    close(cgi_rpipe[0]);
    dup2(cgi_rpipe[1], 1);
    i = 0;
    /* We can use strdup() here because the process will end anyway. */
    akbuf_sprintf(parsebufs[0], "GATEWAY_INTERFACE=CGI/1.1");
    akbuf_asciiz(parsebufs[0]);
    envs[i ++] = strdup(akbuf_data(parsebufs[0]));
    akbuf_asciiz(http_fds[fd].query);
    akbuf_sprintf(parsebufs[0], "QUERY_STRING=%s", akbuf_data(http_fds[fd].query));
    akbuf_asciiz(parsebufs[0]);
    envs[i ++] = strdup(akbuf_data(parsebufs[0]));
    akbuf_sprintf(parsebufs[0], "PATH=" CGI_DEFAULT_PATH);
    akbuf_asciiz(parsebufs[0]);
    envs[i ++] = strdup(akbuf_data(parsebufs[0]));
    akbuf_sprintf(parsebufs[0], "SERVER_SOFTWARE=" SERVER_VERSION);
    akbuf_asciiz(parsebufs[0]);
    envs[i ++] = strdup(akbuf_data(parsebufs[0]));
    akbuf_sprintf(parsebufs[0], "SERVER_PROTOCOL=HTTP/%u.%u", http_fds[fd].ver_maj, http_fds[fd].ver_min);        
    akbuf_asciiz(parsebufs[0]);
    envs[i ++] = strdup(akbuf_data(parsebufs[0]));
    akbuf_clone(parsebufs[1], net_ent->peerbuf);
    if ((j = akbuf_chr(parsebufs[1], ':')) != -1)
    {
      akbuf_split(parsebufs[1], parsebufs[2], j);
      akbuf_asciiz(parsebufs[1]);
      akbuf_sprintf(parsebufs[0], "REMOTE_ADDR=%s", akbuf_data(parsebufs[2]));
      akbuf_asciiz(parsebufs[0]);
      envs[i ++] = strdup(akbuf_data(parsebufs[0]));
      akbuf_sprintf(parsebufs[0], "REMOTE_PORT=%s", akbuf_data(parsebufs[1]));
      akbuf_asciiz(parsebufs[0]);
      envs[i ++] = strdup(akbuf_data(parsebufs[0]));
    }
    akbuf_sprintf(parsebufs[0], "SCRIPT_FILENAME=%s", cgi_name);
    akbuf_asciiz(parsebufs[0]);
    envs[i ++] = strdup(akbuf_data(parsebufs[0]));
    akbuf_sprintf(parsebufs[0], "REQUEST_METHOD=%s", http_method_str(http_fds[fd].method));
    akbuf_asciiz(parsebufs[0]);
    envs[i ++] = strdup(akbuf_data(parsebufs[0]));
    akbuf_asciiz(http_fds[fd].uri);
    akbuf_sprintf(parsebufs[0], "REQUEST_URI=%s", akbuf_data(http_fds[fd].uri));
    akbuf_asciiz(parsebufs[0]);
    envs[i ++] = strdup(akbuf_data(parsebufs[0]));
    if (has_content == 1)
    {
      akbuf_sprintf(parsebufs[0], "CONTENT_LENGTH=%u", (unsigned int)http_fds[fd].content_len);
      akbuf_asciiz(parsebufs[0]);
      envs[i ++] = strdup(akbuf_data(parsebufs[0]));
    }
    envs[i] = NULL;
    execle(cgi_name, cgi_name, NULL, envs);
    akperror("execve() CGI script");
    exit(1);
  }
  if (has_content == 1)
  {
    close(cgi_wpipe[0]);
    net_set_fd(cgi_wpipe[1], NET_FD_SEND, NULL, cgi_handle_sent_content, 1);
    net_send_buf(cgi_wpipe[1], http_fds[fd].content);
    http_fds[fd].wpipe_fd = cgi_wpipe[1];
  }
  DEBUGF("wpipe_fd %d", http_fds[fd].wpipe_fd);
  close(cgi_rpipe[1]);
  net_set_fd(cgi_rpipe[0], NET_FD_READ, cgi_handle_output, NULL, 1);
  http_fds[cgi_rpipe[0]].rpipe_fd = fd;
  http_fds[cgi_rpipe[0]].rpipe_net_ent = net_ent;
  http_fds[cgi_rpipe[0]].ctx = http_fds[fd].ctx;
  http_fds[cgi_rpipe[0]].state = HTTP_FD_CGI;
  http_fds[cgi_rpipe[0]].method = HTTP_METHOD_NONE;
  http_fds[cgi_rpipe[0]].uri = NULL;
  http_fds[cgi_rpipe[0]].query = NULL;
  http_fds[cgi_rpipe[0]].ver_maj = http_fds[fd].ver_min = 0;
  http_fds[cgi_rpipe[0]].keep_alive = 0;
  http_fds[cgi_rpipe[0]].num_headers = 0;
  http_fds[cgi_rpipe[0]].headers = NULL;
  http_fds[cgi_rpipe[0]].num_args = 0;
  http_fds[cgi_rpipe[0]].args = NULL;
  http_fds[fd].state = HTTP_FD_PIPING;
  http_fds[fd].rpipe_fd = cgi_rpipe[0];
  net_set_callbacks(fd, NULL, NULL);
  akbuf_sprintf(net_ent->sendbuf,
    "HTTP/1.1 %u OK\r\n"
    "Server: " SERVER_VERSION "\r\n"
    "Connection: close\r\n",
    HTTP_OK);
  net_send(fd);
  return 0;
}
/* return: 0 == all ok; -1 == error, show errorpage; -2 == error, errorpage shown */
int serve_doc_to_fd(int fd, net_fd_entry *net_ent, unsigned char *orig_doc_name, unsigned char *doc_name, unsigned int doc_off, AKsize_t doc_size, unsigned int add_gzip_header)
{
  unsigned char *mime_type;
  unsigned char timebuf[512];
  unsigned int code;
  struct stat st;
 
  DEBUGF("serve_doc_to_fd() orig [%s] real [%s]", orig_doc_name, doc_name);
  mime_type = get_mime_type(orig_doc_name);
  if (strcasecmp(mime_type, CGI_MIME_TYPE) == 0)
  {
    return serve_cgi_to_fd(fd, net_ent, orig_doc_name); 
  }
  if (access(doc_name, R_OK) != 0) return -1;
  http_log_query(fd, net_ent, HTTP_OK);
  if (http_fds[fd].method != HTTP_METHOD_HEAD && (net_ent->send_fd = open(doc_name, O_RDONLY)) < 0) return -1;
  if (doc_off >= doc_size) doc_off = (doc_size > 0)? doc_size - 1 : 0;
  net_ent->send_fd_off = doc_off;
  net_ent->send_fd_len = doc_size - doc_off;
  code = (doc_off != 0)? HTTP_PARTIAL_CONTENT : HTTP_OK;
  if (http_fds[fd].ver_maj > 0)
  {
    if (stat(doc_name, &st) == 0)
    {
      size_t len;
      struct tm *tmp;
      time_t t;
      
      t = time(NULL);
      tmp = gmtime(&t);
      if ((len = strftime(timebuf, sizeof(timebuf), "%a, %d %b %Y %H:%M:%S %Z", tmp)) == 0) timebuf[0] = 0;
      
    } else
    {
      timebuf[0] = 0;
    }
    if (code == HTTP_PARTIAL_CONTENT)
    {
      akbuf_sprintf(net_ent->sendbuf,
        "HTTP/1.1 %u %s\r\n"
        "Server: " SERVER_VERSION "\r\n"
        "Content-type: %s\r\n"
        "Content-length: %u\r\n"
        "Content-range: bytes %u-%u/%u\r\n"
        "Connection: %s\r\n"
        "Last-Modified: %s\r\n"
        "\r\n",
        code, http_status_msg(code),
        get_mime_type(orig_doc_name),
        doc_size - doc_off,
        doc_off, (doc_size == 0)? 0 : doc_size - 1, doc_size,
        (http_fds[fd].keep_alive == 1)? "keep-alive" : "close",
        timebuf);
    } else
    {
      if (add_gzip_header == 1)
      {
        akbuf_sprintf(net_ent->sendbuf,
          "HTTP/1.1 %u %s\r\n"
          "Server: " SERVER_VERSION "\r\n"
          "Content-type: %s\r\n"
          "Content-length: %u\r\n"
          "Connection: %s\r\n"
          "Last-Modified: %s\r\n"
          "Content-Encoding: gzip\r\n"
          "\r\n",
          code, http_status_msg(code),
          get_mime_type(orig_doc_name),
          doc_size - doc_off,
          (http_fds[fd].keep_alive == 1)? "keep-alive" : "close",
          timebuf);
      
      } else
      {
        akbuf_sprintf(net_ent->sendbuf,
          "HTTP/1.1 %u %s\r\n"
          "Server: " SERVER_VERSION "\r\n"
          "Content-type: %s\r\n"
          "Content-length: %u\r\n"
          "Connection: %s\r\n"
          "Last-Modified: %s\r\n"
          "\r\n",
          code, http_status_msg(code),
          get_mime_type(orig_doc_name),
          doc_size - doc_off,
          (http_fds[fd].keep_alive == 1)? "keep-alive" : "close",
          timebuf);
      }
    }
  }
  net_send(fd);
  return 0;
}
void http_dir_index(int fd, net_fd_entry *net_ent, unsigned char *dir_path)
{
  DIR *dir;
  struct dirent *de;
  struct stat st;
  /* parsebufs: 4 == generated document, 5 == appended data */

  if ((dir = opendir(dir_path)) == NULL)
  {
    http_error(fd, net_ent, (errno == EPERM)? HTTP_FORBIDDEN : HTTP_NOT_FOUND);
    return;
  }
  http_log_query(fd, net_ent, HTTP_OK);
  akbuf_asciiz(http_fds[fd].uri);
  akbuf_sprintf(parsebufs[4],
    "<HTML>\n"
    "<HEAD><TITLE>Index of %s</TITLE></HEAD>\n"
    "<BODY>\n"
    "<H3>Index of %s</H3>\n",
    akbuf_data(http_fds[fd].uri), akbuf_data(http_fds[fd].uri));
  while ((de = readdir(dir)) != NULL)
  {
    akbuf_sprintf(parsebufs[5], "%s/%s", dir_path, de->d_name);
    akbuf_asciiz(parsebufs[5]);
    if (stat(akbuf_data(parsebufs[5]), &st) == 0)
    {
      akbuf_sprintf(parsebufs[5], "<A HREF=\"%s%s\">%s%s</A> %u<BR>\n", de->d_name, (st.st_mode & S_IFDIR)? "/" : "", de->d_name, (st.st_mode & S_IFDIR)? "/" : "", st.st_size);
      akbuf_append_buf(parsebufs[4], parsebufs[5]);
    }
  }
  closedir(dir); /* :-D */
  akbuf_sprintf(parsebufs[5], "</BODY></HTML>\n");
  akbuf_append_buf(parsebufs[4], parsebufs[5]);
  if (http_fds[fd].ver_maj > 0)
  {
    akbuf_sprintf(net_ent->sendbuf,
      "HTTP/1.1 %u OK\r\n"
      "Server: " SERVER_VERSION "\r\n"
      "Content-type: text/html\r\n"
      "Content-length: %u\r\n"
      "Connection: %s\r\n"
      "\r\n",
      HTTP_OK,
      akbuf_idx(parsebufs[4]),
      (http_fds[fd].keep_alive == 1)? "keep-alive" : "close");
  }
  akbuf_append_buf(net_ent->sendbuf, parsebufs[4]);
}
unsigned int http_has_access(akbuf *peerbuf, akbuf *uri)
{
  akbuf_table_entry *ent;
  akbuf *addrbuf;
  akbuf_ctxh ctx;
  int i;
  
  ctx = akbuf_new_ctx();
  addrbuf = akbuf_init(ctx, 0);
  akbuf_clone(addrbuf, peerbuf);
  if ((i = akbuf_chr(addrbuf, ':')) != -1) akbuf_set_byte(addrbuf, i, 0);
  ent = cfg.allow_clients->head;
  while (ent != NULL)
  {
    if (regexec((regex_t *)akbuf_data(ent->key), akbuf_data(addrbuf), 0, NULL, 0) == 0)
    {
      akbuf_asciiz(ent->data);
      akbuf_asciiz(uri);
      if (strncmp(akbuf_data(uri), akbuf_data(ent->data), akbuf_idx(ent->data)) == 0)
      {
        DEBUGF("check_access match [%s] [%s]", akbuf_data(addrbuf), akbuf_data(uri));
        break;
      }
    }
    ent = ent->next;
  }
  if (ent != NULL) return 1;
  ent = cfg.deny_clients->head;
  while (ent != NULL)
  {
    if (regexec((regex_t *)akbuf_data(ent->key), akbuf_data(addrbuf), 0, NULL, 0) == 0)
    {
      akbuf_asciiz(ent->data);
      akbuf_asciiz(uri);
      if (strncmp(akbuf_data(uri), akbuf_data(ent->data), akbuf_idx(ent->data)) == 0)
      {
        DEBUGF("check_access match [%s] [%s]", akbuf_data(addrbuf), akbuf_data(uri));
        break;
      }
    }
    ent = ent->next;
  }
  akbuf_free_ctx(ctx);
  return (ent == NULL)? 1 : 0;
}
void http_do_rewrite(akbuf *rbuf)
{
  akbuf_table_entry *ent;
  unsigned int i, c, rem;
  regmatch_t matches[10];
  /* parsebufs: 6 == saved original rbuf */
  
  akbuf_asciiz(rbuf);
  DEBUGF("doing rewrite on [%s]", akbuf_data(rbuf));
  ent = cfg.rewrite_rules->head;
  while (ent != NULL)
  {
    if (regexec((regex_t *)akbuf_data(ent->key), akbuf_data(rbuf), sizeof(matches) / sizeof(matches[0]), matches, 0) == 0)
    {
      DEBUGF("rewrite regexec() match");
      akbuf_clone(parsebufs[6], rbuf);
      akbuf_set_idx(rbuf, 0);
      i = 0;
      rem = akbuf_idx(ent->data);
      while (rem > 0)
      {
        akbuf_get_byte(ent->data, i, c); i ++; rem --;
        switch (c)
        {
          case '\\':
            if (rem >= 1)
            {
              akbuf_get_byte(ent->data, i, c); i ++; rem --;
              akbuf_append_byte(rbuf, c);
            } else
            {
              aklogf(LOG_ERROR, "Error in rewrite rule: Stray \\ at end of line.");
            }
            break;
          case '$':
            if (rem >= 1)
            {
              akbuf_get_byte(ent->data, i, c) i ++; rem --;
              c -= '0';
              if (c >= sizeof(matches) / sizeof(matches[0]) || matches[c].rm_so == -1)
              {
                aklogf(LOG_ERROR, "Erorr in rewrite rule: Unknown variable $%u.", c);
                break;
              }
              AKassert(matches[c].rm_eo >= matches[c].rm_so);
              akbuf_append_data(rbuf, akbuf_data(parsebufs[6]) + matches[c].rm_so, matches[c].rm_eo - matches[c].rm_so);
            }
            break;
          default:
            akbuf_append_byte(rbuf, c);
            break;
        }
      }
      return;
    } else
    {
      DEBUGF("rewrite regexec() nomatch");
    }
    ent = ent->next;
  }
}
void http_index(int fd, net_fd_entry *net_ent, unsigned char *dir_path, unsigned int doc_off)
{
  unsigned int diridx;
  unsigned int i;
  struct stat st;
  unsigned char *indexdocs[] = { "index.html", "index.htm", NULL };
  /* parsebufs: 3 == full path to try */
    
  akbuf_strcpy(parsebufs[3], dir_path);
  akbuf_append_byte(parsebufs[3], '/');
  diridx = akbuf_idx(parsebufs[3]);
  i = 0;
  while (indexdocs[i] != NULL)
  {
    akbuf_append_str(parsebufs[3], indexdocs[i]);
    akbuf_asciiz(parsebufs[3]);
    DEBUGF("trying index '%s'", akbuf_data(parsebufs[3]));
    if (stat(akbuf_data(parsebufs[3]), &st) == 0 && st.st_mode & S_IFREG)
    {
      if (serve_doc_to_fd(fd, net_ent, akbuf_data(parsebufs[3]), akbuf_data(parsebufs[3]), doc_off, st.st_size, 0) == 0) break;
    }
    akbuf_set_idx(parsebufs[3], diridx);
    i ++;
  }
  if (indexdocs[i] == NULL) http_dir_index(fd, net_ent, dir_path);
}
unsigned int http_parse_range(akbuf *range)
{
  int i;
  unsigned int cur_val, c;
  
  /* XXX support for ranges other than bytes=###- */
  if ((i = akbuf_chr(range, '=')) == -1 || ++ i >= akbuf_idx(range)) return 0;
  cur_val = 0;
  for (; i < akbuf_idx(range); i ++)
  {
    akbuf_get_byte(range, i, c);
    if (c > '9' || c < '0') break;
    c -= '0';
    cur_val *= 10;
    cur_val += c;
  }
  DEBUGF("got range %u", cur_val);
  return cur_val;
}
int http_serve_hook(int fd, net_fd_entry *net_ent)
{
  struct serve_hook_entry
  {
    unsigned char *uri;
    void (*serve_fn)();
  } serve_hooks[] =
  {
    { "announce",	tracker_serve_announce	},
    { "announce.php",	tracker_serve_announce	},
    { "announcephp",	tracker_serve_announce	},
    { "scrape",		tracker_serve_scrape	},
    { "scrape.php",	tracker_serve_scrape	},
    { "scrapephp",	tracker_serve_scrape	},
    { "status",		tracker_serve_status	},
    { "peers",		tracker_serve_peers	},
    { NULL,		NULL			},
  };
  unsigned int i;
  akbuf_ctxh ctx;
  akbuf *uribuf;
  akbuf_asciiz(http_fds[fd].uri);
  
  ctx = akbuf_new_ctx();
  uribuf = akbuf_init(ctx, 0);
  akbuf_clone(uribuf, http_fds[fd].uri);
  while (akbuf_idx(uribuf) > 1 && akbuf_data(uribuf)[0] == '/') akbuf_eat_byte(uribuf); 
  akbuf_asciiz(uribuf);
  i = 0;
  while (serve_hooks[i].uri != NULL)
  {
    if (strcmp(akbuf_data(uribuf), serve_hooks[i].uri) == 0)
    {
      http_log_query(fd, net_ent, HTTP_LOG_HOOK);
      serve_hooks[i].serve_fn(fd, &http_fds[fd], net_ent);
      akbuf_free_ctx(ctx);
      return i;
    }
    i ++;
  }
  akbuf_free_ctx(ctx);
  return -1;
}
void http_serve_req(int fd, net_fd_entry *net_ent)
{
  unsigned char *root_dir, *host_p, *p;
  akbuf_ctxh ctx;
  akbuf *host_buf, *buf;
  unsigned char resolved_path[PATH_MAX + 1], resolved_root[PATH_MAX + 1];
  struct stat st, st2;
  int i;
  unsigned int range_start;
  /* parsebufs: 0 == req path 1 == req path */
  
#define SERVE_ERR(code)\
  {\
    http_error(fd, net_ent, (code));\
    akbuf_free_ctx(ctx);\
    return;\
  }
  
  DEBUGF("serving req");
  ctx = akbuf_new_ctx();
  if ((p = akbuf_table_entry_get_str(http_fds[fd].headers, "Connection")) != NULL)
  {
    DEBUGF("header connection = %s", p);
    if (strcasecmp(p, "keep-alive") == 0) http_fds[fd].keep_alive = 1;
    else if (strcasecmp(p, "close") == 0) http_fds[fd].keep_alive = 0;
  }
  if ((buf = akbuf_table_entry_get(http_fds[fd].headers, "Range")) != NULL)
  {
    range_start = http_parse_range(buf);
  } else
  {
    range_start = 0;
  }
  if ((buf = akbuf_table_entry_get(http_fds[fd].headers, "Host")) != NULL)
  {
    host_buf = akbuf_init(ctx, 0);
    akbuf_clone(host_buf, buf); akbuf_asciiz(host_buf);
    root_dir = akbuf_table_entry_get_str(cfg.vhosts, akbuf_data(host_buf));
    if (root_dir == NULL && (i = akbuf_chr(buf, ':')) != -1)
    {
      akbuf_set_idx(buf, i);
      akbuf_asciiz(buf);
      root_dir = akbuf_table_entry_get_str(cfg.vhosts, akbuf_data(buf));
    }
    if (root_dir == NULL) root_dir = cfg.default_root;
    host_p = akbuf_data(host_buf);
  } else
  {
    if (http_fds[fd].ver_maj > 0 && (http_fds[fd].ver_maj != 1 || http_fds[fd].ver_min != 0)) SERVE_ERR(HTTP_BAD_REQUEST);
    akbuf_asciiz(net_ent->sockbuf);
    host_p = akbuf_data(net_ent->sockbuf);
    root_dir = cfg.default_root;
  }
  DEBUGF("host [%s] root [%s]", host_p, root_dir);
  http_do_rewrite(http_fds[fd].uri);
  akbuf_asciiz(http_fds[fd].uri);
  DEBUGF("rewrote => [%s]", akbuf_data(http_fds[fd].uri));
  if (http_has_access(net_ent->peerbuf, http_fds[fd].uri) == 0) SERVE_ERR(HTTP_FORBIDDEN_BANNED);
  if (http_serve_hook(fd, net_ent) >= 0) { akbuf_free_ctx(ctx); return; }
  if (realpath(root_dir, resolved_root) == NULL) SERVE_ERR((errno == EPERM)? HTTP_FORBIDDEN : HTTP_NOT_FOUND);
  resolved_root[sizeof(resolved_root) - 1] = 0;
  akbuf_strcpy(parsebufs[0], resolved_root);
  akbuf_append_buf(parsebufs[0], http_fds[fd].uri);
  akbuf_asciiz(parsebufs[0]);
  DEBUGF("req path [%s]", akbuf_data(parsebufs[0]));
  if (realpath(akbuf_data(parsebufs[0]), resolved_path) == NULL) SERVE_ERR((errno == EPERM)? HTTP_FORBIDDEN : HTTP_NOT_FOUND);
  resolved_path[sizeof(resolved_path) - 1] = 0;
  DEBUGF("resolved path [%s] root %s", resolved_path, resolved_root);
  if (strlen(resolved_path) < strlen(resolved_root) || strncmp(resolved_path, resolved_root, strlen(resolved_root)) != 0) SERVE_ERR(HTTP_NOT_FOUND);
  
  if (stat(resolved_path, &st) != 0) SERVE_ERR((errno == EPERM)? HTTP_FORBIDDEN : HTTP_NOT_FOUND);
  if (st.st_mode & S_IFDIR)
  {
    unsigned int c;
    
    if (akbuf_empty(http_fds[fd].uri)) SERVE_ERR(HTTP_BAD_REQUEST);
    if (access(resolved_path, X_OK) != 0) SERVE_ERR((errno == EPERM || errno == EACCES)? HTTP_FORBIDDEN : HTTP_NOT_FOUND);
    akbuf_get_byte(http_fds[fd].uri, akbuf_idx(http_fds[fd].uri) - 1, c);
    if (c == '/')
    {
      http_index(fd, net_ent, resolved_path, range_start);
    } else
    {
      http_log_query(fd, net_ent, HTTP_MOVED_PERM);
      akbuf_asciiz(http_fds[fd].uri);
      buf = akbuf_init(ctx, 0);
      akbuf_sprintf(buf,
        "<HTML>\r\n"
        "<HEAD><TITLE>The document has moved</TITLE></HEAD>\r\n"
        "<BODY>New address <A HREF=\"http://%s%s/\">http://%s%s/</a></BODY>\r\n"
        "</HTML>\r\n\r\n",
        host_p, akbuf_data(http_fds[fd].uri),
        host_p, akbuf_data(http_fds[fd].uri));
      akbuf_sprintf(net_ent->sendbuf,
        "HTTP/1.1 %u Moved permanently\r\n"
        "Server: " SERVER_VERSION "\r\n"
        "Content-type: text/html\r\n"
        "Content-length: %u\r\n"
        "Connection: %s\r\n"
        "Location: http://%s%s/\r\n"
        "\r\n",
        HTTP_MOVED_PERM,
        akbuf_idx(buf),
        (http_fds[fd].keep_alive == 1)? "keep-alive" : "close",
        host_p, akbuf_data(http_fds[fd].uri));
      akbuf_append_buf(net_ent->sendbuf, buf);
    }
    net_send(fd);
    akbuf_free_ctx(ctx);
    return;  
  }
  akbuf_strcpy(parsebufs[0], resolved_path);
  akbuf_append_byte(parsebufs[0], '.');
  akbuf_append_str(parsebufs[0], GZIP_SUFFIX);
  akbuf_asciiz(parsebufs[0]);
  if (akbuf_table_entry_get(http_fds[fd].headers, "Accept-Encoding") != NULL && stat(akbuf_data(parsebufs[0]), &st2) == 0 && !(st2.st_mode & S_IFDIR))
  {
    if (serve_doc_to_fd(fd, net_ent, resolved_path, akbuf_data(parsebufs[0]), range_start, st2.st_size, 1) == -1) SERVE_ERR((errno == EPERM || errno == EACCES)? HTTP_FORBIDDEN : HTTP_NOT_FOUND);
  } else
  {
    if (serve_doc_to_fd(fd, net_ent, resolved_path, resolved_path, range_start, st.st_size, 0) == -1) SERVE_ERR((errno == EPERM || errno == EACCES)? HTTP_FORBIDDEN : HTTP_NOT_FOUND);
  }
  akbuf_free_ctx(ctx);
}
AKssize_t http_unescape(akbuf *inbuf, akbuf *outbuf)
{
  unsigned int rem, i, c, d;
  akbuf_ctxh ctx;
  akbuf *buf;
  
  ctx = AKbuf_INVALID_CTX;
  if (outbuf == NULL)
  {
    ctx = akbuf_new_ctx();
    buf = akbuf_init(ctx, akbuf_idx(inbuf));
  } else
  {
    buf = outbuf;
  }
  i = 0;
  rem = akbuf_idx(inbuf);
  while (rem > 0)
  {
    akbuf_get_byte(inbuf, i, d); i ++; rem --;
    if (d == '%' && rem >= 2)
    {
      akbuf_get_byte(inbuf, i, c); i ++; rem --;
      if (c >= 'a') c -= 'a' - 0xa;
      else if (c >= 'A') c -= 'A' - 0xa;
      else if (c >= '0') c -= '0';
      else break;
      d = c << 4;
      akbuf_get_byte(inbuf, i, c); i ++; rem --;
      if (c >= 'a') c -= 'a' - 0xa;
      else if (c >= 'A') c -= 'A' - 0xa;
      else if (c >= '0') c -= '0';
      else break;
      d |= c;
      if (d > 0xff) break;
    }
    akbuf_append_byte(buf, d);
  }
  if (rem > 0) { if (ctx != AKbuf_INVALID_CTX) akbuf_free_ctx(ctx); return -rem; }
  if (outbuf == NULL) akbuf_clone(inbuf, buf);
  if (ctx != AKbuf_INVALID_CTX) akbuf_free_ctx(ctx);
  return i;
}
void http_parse_arg(akbuf *arg, akbuf *var, akbuf *val)
{
  int i;
    
  akbuf_set_idx(var, 0);
  akbuf_set_idx(val, 0);
  if ((i = akbuf_chr(arg, '=')) != -1)
  {
    akbuf_split(arg, var, i);
    akbuf_clone(val, arg);
  } else
  {
    akbuf_clone(var, arg);
  }
  http_unescape(var, NULL);
  http_unescape(val, NULL);
}
void http_parse_args(int fd, net_fd_entry *net_ent, akbuf *args)
{
  akbuf_ctxh ctx;
  akbuf *splitargs, *splitarg;
  akbuf *var, *val;
  int i;
  
  ctx = akbuf_new_ctx();
  splitargs = akbuf_init(ctx, 0);
  splitarg = akbuf_init(ctx, 0);
  var = akbuf_init(ctx, 0);
  val = akbuf_init(ctx, 0);
  akbuf_clone(splitargs, args);
  while ((i = akbuf_chr(splitargs, '&')) != -1) 
  {
    akbuf_split(splitargs, splitarg, i);
    http_parse_arg(splitarg, var, val);
    akbuf_asciiz(var);
#ifdef DEBUG
    akbuf_asciiz(val);
    DEBUGF("http_parse_args(): var [%s] val [%s]\n", akbuf_data(var), akbuf_data(val));
#endif
    akbuf_table_entry_add(http_fds[fd].ctx, http_fds[fd].args, akbuf_data(var), val);
  }
  if (akbuf_idx(splitargs) > 0)
  {
    http_parse_arg(splitargs, var, val);
    akbuf_asciiz(var);
#ifdef DEBUG
    akbuf_asciiz(val);
    DEBUGF("http_parse_args(): last var [%s] val [%s]\n", akbuf_data(var), akbuf_data(val));
#endif
    akbuf_table_entry_add(http_fds[fd].ctx, http_fds[fd].args, akbuf_data(var), val); 
  }
  akbuf_free_ctx(ctx);  
}
void http_handle_action(int fd, net_fd_entry *net_ent, akbuf *linebuf)
{
  int i;
  unsigned int c;
  /* parsebufs: 0 == method, 1 == uri */
  
#define ACTION_ERR()\
  {\
    http_error(fd, net_ent, HTTP_BAD_REQUEST);\
    return;\
  }
  
  DEBUGF("http action");
  if ((i = akbuf_chr(linebuf, ' ')) == -1) ACTION_ERR();
  akbuf_split(linebuf, parsebufs[0], i);
  akbuf_asciiz(parsebufs[0]);
  if (strcasecmp(akbuf_data(parsebufs[0]), "GET") == 0) http_fds[fd].method = HTTP_METHOD_GET;
  else if (strcasecmp(akbuf_data(parsebufs[0]), "HEAD") == 0) http_fds[fd].method = HTTP_METHOD_HEAD;
  else if (strcasecmp(akbuf_data(parsebufs[0]), "POST") == 0) http_fds[fd].method = HTTP_METHOD_POST;
  else ACTION_ERR();
  if ((i = akbuf_chr(linebuf, ' ')) != -1)
  {
    unsigned int cur_ver, seen_dot;

    akbuf_split(linebuf, parsebufs[1], i);
    if ((i = akbuf_chr(linebuf, '/')) == -1) ACTION_ERR();
    if (++ i >= akbuf_idx(linebuf)) ACTION_ERR();
    cur_ver = seen_dot = 0;
    for (; i < akbuf_idx(linebuf); i ++)
    {
      akbuf_get_byte(linebuf, i, c);
      if (c == '.')
      {
        if (seen_dot == 0) http_fds[fd].ver_maj = cur_ver;
        else if (seen_dot == 1) http_fds[fd].ver_min = cur_ver;
        seen_dot ++;
        cur_ver = 0;
      } else
      {
        if (c > '9' || c < '0') ACTION_ERR();
        cur_ver *= 10;
        cur_ver += c - '0';
      }
    }
    if (seen_dot == 0) http_fds[fd].ver_maj = cur_ver;
    else if (seen_dot == 1) http_fds[fd].ver_min = cur_ver;
  } else
  {
    akbuf_clone(parsebufs[1], linebuf);
    http_fds[fd].ver_maj = 0;
    http_fds[fd].ver_min = 9;
  }
  if ((i = akbuf_chr(parsebufs[1], '?')) != -1)
  {
    if (i == 0) ACTION_ERR();
    akbuf_set_data(http_fds[fd].query, akbuf_data(parsebufs[1]) + i + 1, akbuf_idx(parsebufs[1]) - i - 1);
    akbuf_set_idx(parsebufs[1], i);
    akbuf_asciiz(http_fds[fd].query); akbuf_asciiz(parsebufs[1]);
    DEBUGF("got query [%s] rem [%s]", akbuf_data(http_fds[fd].query), akbuf_data(parsebufs[1]));
    http_parse_args(fd, net_ent, http_fds[fd].query);
  } else
  {
    akbuf_set_idx(http_fds[fd].query, 0);
  }
  if (akbuf_empty(parsebufs[1])) ACTION_ERR();
  http_unescape(parsebufs[1], http_fds[fd].uri);
  if (akbuf_empty(http_fds[fd].uri)) ACTION_ERR();
  akbuf_asciiz(http_fds[fd].uri);
  DEBUGF("got http version %u.%u", http_fds[fd].ver_maj, http_fds[fd].ver_min);
  akbuf_asciiz(net_ent->peerbuf);
  aklogf(LOG_DEBUG, "%d: %s HTTP/%u.%u \"%s %s\"", fd,  akbuf_data(net_ent->peerbuf), http_fds[fd].ver_maj, http_fds[fd].ver_min, akbuf_data(parsebufs[0]), akbuf_data(http_fds[fd].uri));
  if (http_fds[fd].ver_maj > 0) http_fds[fd].state = HTTP_FD_HEADERS; else http_serve_req(fd, net_ent);
}
void http_handle_content(int fd, net_fd_entry *net_ent, akbuf *buf)
{
  unsigned int rem;
  
  rem = http_fds[fd].content_len - akbuf_idx(http_fds[fd].content);
  akbuf_append_data(http_fds[fd].content, akbuf_data(buf), (akbuf_idx(buf) > rem)? rem : akbuf_idx(buf));
  if (akbuf_idx(http_fds[fd].content) >= http_fds[fd].content_len)
  {
    http_serve_req(fd, net_ent);
    return;
  }
}
void http_handle_headers(int fd, net_fd_entry *net_ent, akbuf *linebuf)
{
  int i;
  /* parsebufs: 0 == header name */
    
#define HEADERS_ERR()\
  {\
    http_error(fd, net_ent, HTTP_BAD_REQUEST);\
    return;\
  }
  
  if (akbuf_empty(linebuf) || (i = akbuf_chr(linebuf, ':')) == -1) 
  {
    DEBUGF("content-len %u", http_fds[fd].content_len);
    if (http_fds[fd].content_len != 0)
    {
      http_fds[fd].state = HTTP_FD_CONTENT;
      net_set_callbacks(fd, http_handle_content, http_handle_sent);
      net_set_type(fd, NET_FD_READ);
    } else
    {
      http_serve_req(fd, net_ent);
    }
    return;
  }
  if (http_fds[fd].num_headers >= HTTP_MAX_HEADERS) HEADERS_ERR();
  akbuf_split(linebuf, parsebufs[0], i);
  for (i = 0; i < akbuf_idx(linebuf); i ++) if (akbuf_data(linebuf)[i] != ' ' && akbuf_data(linebuf)[i] != '\t') break;
  akbuf_consume(linebuf, i);
  akbuf_asciiz(parsebufs[0]); akbuf_asciiz(linebuf);
  DEBUGF("header [%s] : [%s]", akbuf_data(parsebufs[0]), akbuf_data(linebuf));
  if (strcasecmp(akbuf_data(parsebufs[0]), "Content-length") == 0)
  {
    http_fds[fd].content_len = atoi(akbuf_data(linebuf));
    if (http_fds[fd].content_len > HTTP_MAX_CONTENT_LEN) HEADERS_ERR();
  }
  akbuf_table_entry_add(http_fds[fd].ctx, http_fds[fd].headers, akbuf_data(parsebufs[0]), linebuf);
  return;
}
void http_handle_action_and_headers(int fd, net_fd_entry *net_ent, akbuf *linebuf)
{
  unsigned int i;
  
  for (i = 0; i < sizeof(parsebufs) / sizeof(parsebufs[0]); i ++) if (akbuf_size(parsebufs[i]) > BUF_SIZE) akbuf_set_size(parsebufs[i], BUF_SIZE);
  switch (http_fds[fd].state)
  {
    case HTTP_FD_UNUSED:
    case HTTP_FD_NEW_REQ:
      http_fds[fd].ctx = net_ent->ctx;
      http_fds[fd].state = HTTP_FD_ACTION;
      http_fds[fd].method = HTTP_METHOD_NONE;
      http_fds[fd].uri = akbuf_init(net_ent->ctx, 0);
      http_fds[fd].query = akbuf_init(net_ent->ctx, 0);
      http_fds[fd].content = akbuf_init(net_ent->ctx, 0);
      http_fds[fd].content_len = 0;
      http_fds[fd].ver_maj = http_fds[fd].ver_min = 0;
      http_fds[fd].keep_alive = 0;
      http_fds[fd].num_headers = 0;
      http_fds[fd].headers = akbuf_table_init(net_ent->ctx, AKBUF_TABLE_NOCASE);
      http_fds[fd].num_args = 0;
      http_fds[fd].args = akbuf_table_init(net_ent->ctx, AKBUF_TABLE_NOCASE);
      http_fds[fd].rpipe_fd = -1;
      http_fds[fd].rpipe_net_ent = NULL;
      http_fds[fd].wpipe_fd = -1;
      http_fds[fd].wpipe_net_ent = NULL;
      /* fallthrough */
    case HTTP_FD_ACTION:
      http_handle_action(fd, net_ent, linebuf);
      break;
    case HTTP_FD_HEADERS:
      http_handle_headers(fd, net_ent, linebuf);
      break;
  }
}
