typedef struct tracker_config_s tracker_config;
struct tracker_config_s
{
  unsigned int interval;
  unsigned int init_interval;
  unsigned int timeout;
  unsigned int stopped_timeout;
  unsigned int respnum;
  unsigned int period;
  unsigned char *statslog;
  unsigned int sql_stats;
  unsigned char *sql_host;
  unsigned char *sql_db;
  unsigned char *sql_user;
  unsigned char *sql_pass;
  unsigned int sync;
  unsigned int sync_interval;
  unsigned int sync_size;
  struct in_addr sync_addr;
  unsigned int sync_port;
  unsigned char *infohash_file;
  unsigned int infohash_interval;
};

typedef struct hypercube_config_s hypercube_config;

struct hypercube_config_s
{
  int listen_port;
  struct in_addr listen_addr;
  unsigned char *default_root;
  unsigned int log;
  unsigned char *log_level;
  unsigned char *log_file;
  unsigned int background;
  int run_as_uid;
  int run_as_gid;
  unsigned char *chroot_dir;
  akbuf_table *vhosts;
  akbuf_table *mime_types;
  akbuf_table *rewrite_rules;
  akbuf_table *allow_clients;
  akbuf_table *deny_clients;
  tracker_config tracker;
};

int cfg_load(unsigned char *, unsigned int);
void cfg_init(void);
void cfg_reload(void);
