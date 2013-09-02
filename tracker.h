#define ID_LEN 20

#define PEER_HASH_SIZE		0x100000
#define PEER_HASH_SEARCH_DELTA	0x4
#define PEER_HASH_FN(info_hash)	(hash_buf(info_hash) & (PEER_HASH_SIZE - 1))

enum { EVENT_NONE, EVENT_STARTED, EVENT_COMPLETED, EVENT_STOPPED };

struct ipmask_entry_s
{
  unsigned char *ipaddr;
  unsigned char *netmask;
};
typedef struct ipmask_entry_s ipmask_entry;

struct peer_entry_s
{
  unsigned int hash_idx;
  unsigned int peer_hash_idx;
  unsigned int num_hits;
  unsigned int num_seeders, num_leechers, times_completed;
  unsigned int is_seeder;
  unsigned char info_hash[ID_LEN];
  unsigned char peer_id[ID_LEN];
  time_t prev_active;
  time_t last_active;
  unsigned char ipstr[64];
  unsigned int ipnum;
  unsigned char ipraw[4];
  unsigned int port;
  unsigned long long uploaded;
  unsigned long long downloaded;
  unsigned long long prev_uploaded;
  unsigned long long prev_downloaded;
  unsigned int lastevent;
  unsigned int is_local;
  unsigned int is_complete;
  struct peer_entry_s *next;
  struct peer_entry_s *prev;
};
typedef struct peer_entry_s peer_entry;

void tracker_init(void);
void tracker_periodic(void);
void tracker_serve_announce(int, http_fd_entry *, net_fd_entry *);
void tracker_serve_scrape(int, http_fd_entry *, net_fd_entry *);
void tracker_serve_status(int, http_fd_entry *, net_fd_entry *);
void tracker_serve_peers(int, http_fd_entry *, net_fd_entry *);
