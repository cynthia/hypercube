#include "hypercube.h"

extern hypercube_config cfg;

peer_entry *torrent_hash[PEER_HASH_SIZE];
peer_entry *peer_hash[PEER_HASH_SIZE];

#ifdef INFOHASH_RESTRICTION
unsigned int infohash_allowed[PEER_HASH_SIZE];
static time_t last_infohash_period;
#endif

unsigned int num_peers, num_torrents, num_seeders, num_leechers;
unsigned int peers_mem_size;

unsigned int announce_count, scrape_count, status_count, peers_count;

static time_t last_period;

static akbuf_ctxh tracker_ctx;
akbuf *syncbuf;

ipmask_entry telia_addrs[] =
{
#include "telia.h"
  { NULL, NULL }
};

void benc_str(akbuf *bencbuf, unsigned char *str)
{
  akbuf_appendf(bencbuf, "%u:%s", strlen(str), str);
}
void benc_int(akbuf *bencbuf, int i)
{
  akbuf_appendf(bencbuf, "i%de", i);
}
void benc_raw(akbuf *bencbuf, unsigned char *data, AKsize_t len)
{
  akbuf_appendf(bencbuf, "%u:", len);
  akbuf_append_data(bencbuf, data, len);
}
void benc_buf(akbuf *bencbuf, akbuf *buf)
{
  benc_raw(bencbuf, akbuf_data(buf), akbuf_idx(buf));
}
void benc_key_raw(akbuf *bencbuf, unsigned char *key, unsigned char *val, AKsize_t val_len)
{
  benc_str(bencbuf, key);
  benc_raw(bencbuf, val, val_len);
}
void benc_key_buf(akbuf *bencbuf, unsigned char *key, akbuf *valbuf)
{
  benc_str(bencbuf, key);
  benc_buf(bencbuf, valbuf);
}
void benc_key_int(akbuf *bencbuf, unsigned char *key, int val)
{
  benc_str(bencbuf, key);
  benc_int(bencbuf, val);
}
void benc_key(akbuf *bencbuf, unsigned char *key, unsigned char *val)
{
  benc_str(bencbuf, key);
  benc_str(bencbuf, val);
}
void benc_out_dict(akbuf *bencbuf, akbuf *outbuf)
{
  akbuf_append_byte(outbuf, 'd');
  akbuf_append_buf(outbuf, bencbuf);
  akbuf_append_byte(outbuf, 'e');
}
void benc_out_list(akbuf *bencbuf, akbuf *outbuf)
{
  akbuf_append_byte(outbuf, 'l');
  akbuf_append_buf(outbuf, bencbuf);
  akbuf_append_byte(outbuf, 'e');
}

void tracker_http_response(int fd, http_fd_entry *http_ent, net_fd_entry *net_ent, unsigned int code, unsigned char *content_type)
{
  net_send(fd);
  http_ent->keep_alive = 0;
  if (http_ent->ver_maj == 0) return;
  akbuf_sprintf(net_ent->sendbuf,
    "HTTP/%u.%u %u %s\r\n"
    "Server: " SERVER_VERSION "\r\n"
    "Content-type: %s\r\n"
    "Connection: close\r\n"
    "Pragma: no-cache\r\n"
    "\r\n",
    http_ent->ver_maj, http_ent->ver_min,
    code, http_status_msg(code),
    content_type);
}
void tracker_benc_response(int fd, http_fd_entry *http_ent, net_fd_entry *net_ent, akbuf *bencbuf)
{
  tracker_http_response(fd, http_ent, net_ent, HTTP_OK, "text/plain");
  benc_out_dict(bencbuf, net_ent->sendbuf);
#ifdef DEBUG
  {
    unsigned int i, c;
    
    for (i = 0; i < akbuf_idx(bencbuf); i ++)
    {
      akbuf_get_byte(bencbuf, i, c);
      if (c == 0) akbuf_set_byte(bencbuf, i, '.');
    }
    akbuf_asciiz(bencbuf);
    DEBUGF("sending bencoded response (%u byte(s)): [%s]\n", akbuf_idx(bencbuf), akbuf_data(bencbuf));
  }
#endif
}

unsigned int hash_buf(akbuf *buf)
{
  unsigned int i, c;
  unsigned char curhash[4];
  
  memcpy(curhash, "\xf0\x0f\xc7\xc8", 4);
  for (i = 0; i < akbuf_idx(buf); i ++)
  {
    akbuf_get_byte(buf, i, c);
    curhash[i & 3] ^= c;
  }
  return (curhash[0] << 24) | (curhash[1] << 16) | (curhash[2] << 8) | curhash[3];
}

peer_entry *peer_get(akbuf *peer_id, akbuf *info_hash, unsigned int alloc_new)
{
  peer_entry *peer, *cur;
  unsigned int idx, pidx, i, free_idx;
  
  AKdassert(akbuf_idx(peer_id) == ID_LEN && akbuf_idx(info_hash) == ID_LEN);
  pidx = PEER_HASH_FN(peer_id);
  if (peer_hash[pidx] != NULL &&
      memcmp(peer_hash[pidx]->peer_id, akbuf_data(peer_id), ID_LEN) == 0 &&
      memcmp(peer_hash[pidx]->info_hash, akbuf_data(info_hash), ID_LEN) == 0)
  {
    DEBUGF("found peer in peer_hash");
    return peer_hash[pidx];
  }
  free_idx = (unsigned int)-1;
  idx = PEER_HASH_FN(info_hash); 
  peer = NULL;
  for (i = 0; i < PEER_HASH_SEARCH_DELTA; i ++)
  {
    if ((cur = torrent_hash[idx]) == NULL && free_idx == (unsigned int)-1) free_idx = idx;
    if (cur != NULL && memcmp(cur->info_hash, akbuf_data(info_hash), ID_LEN) == 0)
    {
      peer = cur;
      break;
    }
    idx ++;
    if (idx >= PEER_HASH_SIZE) idx = 0;
  }
  if (i == PEER_HASH_SEARCH_DELTA)
  {
    if (free_idx == (unsigned int)-1) return NULL;
    idx = free_idx;
  } else
  {
    while (peer != NULL)
    {
      if (memcmp(peer->peer_id, akbuf_data(peer_id), ID_LEN) == 0) break;
      peer = peer->next;
    }
  }
  if (peer == NULL && alloc_new == 1)
  {
    peer = malloc(sizeof(peer_entry));
    peers_mem_size += sizeof(peer_entry);
    num_peers ++;
    peer->num_hits = peer->num_seeders = peer->num_leechers = peer->times_completed = 0;
    peer->uploaded = peer->downloaded = 0;
    peer->prev_uploaded = peer->prev_downloaded = 0;
    peer->lastevent = 0;
    peer->last_active = peer->prev_active = (time_t)0;
    peer->is_complete = 0;
    memcpy(peer->peer_id, akbuf_data(peer_id), ID_LEN);
    memcpy(peer->info_hash, akbuf_data(info_hash), ID_LEN);
    peer->hash_idx = idx;
    peer->peer_hash_idx = pidx;
    peer->prev = NULL;
    if ((peer->next = torrent_hash[idx]) != NULL) peer->next->prev = peer;
    torrent_hash[idx] = peer;
    peer_hash[pidx] = peer;
  }
  return peer;
}
void peer_del(peer_entry *peer)
{
  if (peer_hash[peer->peer_hash_idx] == peer) peer_hash[peer->peer_hash_idx] = NULL;
  if (peer->prev != NULL) peer->prev->next = peer->next;
  if (peer->next != NULL) peer->next->prev = peer->prev;
  if (peer == torrent_hash[peer->hash_idx])
  {
    if (peer->next != NULL)
    {
      peer->next->num_seeders = peer->num_seeders;
      peer->next->num_leechers = peer->num_leechers;
      peer->next->times_completed = peer->times_completed;
    }
    torrent_hash[peer->hash_idx] = peer->next;
  }
  num_peers --;
  free(peer);
  peers_mem_size -= sizeof(peer_entry);
}
void scramble_peers(void)
{
  unsigned int i, j, newpeerscount;
  peer_entry *peer, *prevpeer, *headpeer;
  
  DEBUGF("scrambling peers\n");
  for (i = 0; i < PEER_HASH_SIZE; i ++) if ((peer = headpeer = torrent_hash[i]) != NULL)
  {
    if ((headpeer->num_seeders + headpeer->num_leechers) > 1) // cfg.tracker.respnum)
    {
      newpeerscount = 0;
      peer = headpeer;
      j = rand() % ((headpeer->num_seeders + headpeer->num_leechers) >> 1);
      while (j > 0 && peer != NULL) { peer = peer->next; j --; }
      if (peer == NULL || peer == headpeer) continue;
      while (peer != NULL && newpeerscount < cfg.tracker.respnum)
      {
        prevpeer = peer;
        peer = peer->next;
        if ((rand() & 7) == 3)
        {
          if (prevpeer->prev != NULL) prevpeer->prev->next = prevpeer->next;
          if (prevpeer->next != NULL) prevpeer->next->prev = prevpeer->prev;
          prevpeer->next = headpeer->next;
          prevpeer->prev = headpeer;
          headpeer->next = prevpeer;
          newpeerscount ++;
        }        
      }
    }
  }
}
unsigned int is_telia(unsigned int ipaddr)
{
  unsigned int i;
  unsigned int cipaddr, cmask;
  i = 0;
  while (telia_addrs[i].ipaddr != NULL)
  {
    cipaddr = ntohl(inet_addr(telia_addrs[i].ipaddr));
    cmask = ntohl(inet_addr(telia_addrs[i].netmask));
    if ((cipaddr & cmask) == (ipaddr & cmask)) return 1;
    i ++;
  }
  return 0;
}
void send_peers(akbuf *outbuf, peer_entry *curpeer, unsigned int send_seeders, unsigned int do_compact, unsigned int only_telia)
{
  peer_entry *peer, *headpeer, *sendpeers[cfg.tracker.respnum];
  unsigned int num_sendpeers, i, j;
  akbuf_ctxh ctx;
  akbuf *buf;
  
  for (i = 0; i < cfg.tracker.respnum; i ++) sendpeers[i] = NULL;
  num_sendpeers = 0;
  peer = headpeer = torrent_hash[curpeer->hash_idx];
  if (headpeer != NULL && (j = headpeer->num_seeders + headpeer->num_leechers) >= cfg.tracker.respnum * 2)
  {
    for (i = rand() % (j - cfg.tracker.respnum); i > 0; i --)
    {
      if ((peer = peer->next) == NULL) peer = headpeer;
    }
  }
  while (num_sendpeers < cfg.tracker.respnum && peer != NULL)
  {
    if (peer != curpeer && (only_telia == 0 || is_telia(peer->ipnum) == 1))
    {
      for (i = 0; i < cfg.tracker.respnum; i ++) if (sendpeers[i] == peer) break;
      if (i == cfg.tracker.respnum && (send_seeders == 1 || peer->is_seeder == 0))
      {
        j = rand() & (cfg.tracker.respnum - 1);
        if (sendpeers[j] == NULL)
        {
          sendpeers[j] = peer;
          num_sendpeers ++;
          peer->num_hits ++;
        }
      }
    }
    peer = peer->next;
  }  
  ctx = akbuf_new_ctx();
  buf = akbuf_init(ctx, 0);
  for (i = 0; i < cfg.tracker.respnum; i ++)
  {
    if (sendpeers[i] != NULL)
    {  
      akbuf_set_idx(buf, 0);
      if (do_compact == 1)
      {
        akbuf_append_data(outbuf, sendpeers[i]->ipraw, sizeof(sendpeers[i]->ipraw));
        akbuf_append_byte(outbuf, (sendpeers[i]->port >> 8) & 0xff);
        akbuf_append_byte(outbuf, sendpeers[i]->port & 0xff);
      } else
      {
        benc_key(buf, "ip", sendpeers[i]->ipstr);
        benc_key_raw(buf, "peer id", sendpeers[i]->peer_id, ID_LEN);
        benc_key_int(buf, "port", sendpeers[i]->port);
        benc_out_dict(buf, outbuf);
      }
      sendpeers[i] = NULL;
    }
  }  
  akbuf_free_ctx(ctx);
}

/*
 * synchronization packet:
 * each entry:
 * [magic 'AKhc' 4 bytes]
 * [info hash 20 bytes][peer id 20 bytes]
 * [ip addr 4 bytes][port 2 bytes]
 * [is seeder 1 byte]
 * [padding 1 byte]
 * total entry len: 48 bytes
 */

#define SYNC_ENTRY_LEN		(2 + ID_LEN * 2 + 4 + 2 + 1 + 1)
#define SYNC_ENTRY_MAGIC	"AKhc"
#define SYNC_ENTRY_MAGIC_LEN	4

void handle_sync_packet(int fd, net_fd_entry *net_ent, void *dummy)
{
  ssize_t n;
  struct sockaddr_in fromsin;
  socklen_t sin_len;
  akbuf_ctxh ctx;
  akbuf *buf;
  akbuf *peer_id, *info_hash;
  unsigned char ipraw[4];
  unsigned int ipnum, port;
  unsigned int is_seeder;
  peer_entry *peer;
  struct in_addr in;
  
  DEBUGF("got sync packet");
  ctx = akbuf_new_ctx();
  buf = akbuf_init(ctx, cfg.tracker.sync_size + 100);
  sin_len = sizeof(fromsin);
  if ((n = recvfrom(fd, akbuf_data(buf), akbuf_size(buf), 0, (struct sockaddr *)&fromsin, &sin_len)) <= 0)
  {
    akperror("tracker.c:handle_sync_packet():recvfrom()");
    akbuf_free_ctx(ctx);
    return;
  }
  akbuf_set_idx(buf, n);
  DEBUGF("got sync packet from %s:%u", inet_ntoa(fromsin.sin_addr), ntohs(fromsin.sin_port));
  DEBUGF("sync packet is %u bytes", akbuf_idx(buf));
  peer_id = akbuf_init(ctx, ID_LEN);
  info_hash = akbuf_init(ctx, ID_LEN);
  while (akbuf_idx(buf) >= SYNC_ENTRY_LEN)
  {
    if (memcmp(akbuf_data(buf), SYNC_ENTRY_MAGIC, SYNC_ENTRY_MAGIC_LEN) != 0)
    {
      DEBUGF("malformed sync entry, invalid magic %.2x%.2x%.2x%.2x", akbuf_data(buf)[0], akbuf_data(buf)[1], akbuf_data(buf)[2], akbuf_data(buf)[3]);
      break;
    }
    akbuf_consume(buf, SYNC_ENTRY_MAGIC_LEN);
    akbuf_set_data(info_hash, akbuf_data(buf), ID_LEN); akbuf_consume(buf, ID_LEN);
    akbuf_set_data(peer_id, akbuf_data(buf), ID_LEN); akbuf_consume(buf, ID_LEN);
    ipraw[0] = akbuf_eat_byte(buf);
    ipraw[1] = akbuf_eat_byte(buf);
    ipraw[2] = akbuf_eat_byte(buf);
    ipraw[3] = akbuf_eat_byte(buf);
    port = (akbuf_eat_byte(buf) << 8) | akbuf_eat_byte(buf);
    is_seeder = akbuf_eat_byte(buf);
    akbuf_eat_byte(buf); /* eat padding */
    DEBUGF("sync entry: ipraw %.2x%.2x%.2x%.2x port %x is_seeder %u", ipraw[0], ipraw[1], ipraw[2], ipraw[3], port, is_seeder);
    if ((peer = peer_get(peer_id, info_hash, 1)) == NULL)
    {
      aklogf(LOG_ERROR, "tracker.c:handle_sync_packet(): peer_get() failed!");
    } else
    {
      peer->last_active = time(NULL);
      peer->lastevent = 0;
      peer->is_local = 0;
      peer->is_seeder = is_seeder;
      memcpy(peer->ipraw, ipraw, 4);
      peer->port = port;
      ipnum = (ipraw[0] << 24) | (ipraw[1] << 16) | (ipraw[2] << 8) | ipraw[3];
      in.s_addr = peer->ipnum = htonl(ipnum);
      AKstrcpy(peer->ipstr, inet_ntoa(in)); 
      DEBUGF("peer->ipstr = '%s' peer->port = %u", peer->ipstr, peer->port);
      DEBUGF("torrent hash idx %u peer hash idx %u", peer->hash_idx, peer->peer_hash_idx);
    }
  }
  if (akbuf_idx(buf) > 0)
  {
    DEBUGF("malformed sync entry, %u byte(s) left", akbuf_idx(buf));
  }
  akbuf_free_ctx(ctx);
}

#ifdef INFOHASH_RESTRICTION
void read_infohash_file(void)
{
  unsigned int i;
  int fd;
  akbuf *readbuf;
  akbuf_ctxh ctx;
  
  for (i = 0; i < PEER_HASH_SIZE; i ++) infohash_allowed[i] = 0;
  if (cfg.tracker.infohash_file == NULL || (fd = open(cfg.tracker.infohash_file, O_RDONLY)) == -1)
  {
    for (i = 0; i < PEER_HASH_SIZE; i ++) infohash_allowed[i] = 1;
    return;    
  }
  ctx = akbuf_new_ctx();
  readbuf = akbuf_init(ctx, ID_LEN);
  akbuf_set_idx(readbuf, ID_LEN);
  while (read(fd, akbuf_data(readbuf), ID_LEN) == ID_LEN)
  {
    infohash_allowed[PEER_HASH_FN(readbuf)] = 1;
  }
  close(fd);
  akbuf_free_ctx(ctx);
}
void init_infohash_restriction(void)
{
  unsigned int i;
  
  last_infohash_period = 0;
  for (i = 0; i < PEER_HASH_SIZE; i ++) infohash_allowed[i] = 1;
  //read_infohash_file();
}
#endif

void init_sync(void)
{
  int s;
  struct sockaddr_in sin;
  
  syncbuf = akbuf_init(tracker_ctx, cfg.tracker.sync_size);
  if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 || s >= ASIO_MAX_FDS)
  {
    akperror("tracker.c:init_sync():socket()");
    return;
  }
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons(cfg.tracker.sync_port);
  if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) != 0)
  {
    akperror("tracker.c:init_sync():bind()");
    return;
  }
  net_set_fd(s, NET_FD_RAW, handle_sync_packet, NULL, 0);
  aklogf(LOG_INFO, "Tracker sync listening on UDP port %u", cfg.tracker.sync_port);
}
void do_sync(void)
{
  int s;
  struct sockaddr_in sin;
  
  if (akbuf_idx(syncbuf) == 0) return;
  if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
  {
    akperror("tracker.c:do_sync():socket()");
    return;
  }
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = 0;
  if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) != 0)
  {
    akperror("tracker.c:do_sync():bind()");
    close(s);
    return;
  }
  sin.sin_addr.s_addr = cfg.tracker.sync_addr.s_addr;
  sin.sin_port = htons(cfg.tracker.sync_port);
  DEBUGF("syncing %u bytes", akbuf_idx(syncbuf));
  if (sendto(s, akbuf_data(syncbuf), akbuf_idx(syncbuf), 0, (struct sockaddr *)&sin, sizeof(sin)) != akbuf_idx(syncbuf))
  {
    akperror("tracker.c:do_sync():sendto()");
    close(s);
    return;
  } 
  akbuf_set_idx(syncbuf, 0);
  DEBUGF("sent sync packet");
}
void sync_peer(peer_entry *peer)
{
  akbuf_append_str(syncbuf, SYNC_ENTRY_MAGIC);
  akbuf_append_data(syncbuf, peer->info_hash, ID_LEN);
  akbuf_append_data(syncbuf, peer->peer_id, ID_LEN);
  akbuf_append_data(syncbuf, peer->ipraw, sizeof(peer->ipraw));
  akbuf_append_byte(syncbuf, (peer->port >> 8) & 0xff);
  akbuf_append_byte(syncbuf, peer->port & 0xff);
  akbuf_append_byte(syncbuf, peer->is_seeder & 0xff);
  akbuf_append_byte(syncbuf, 42);
  if (akbuf_idx(syncbuf) >= cfg.tracker.sync_size) do_sync();
}

void tracker_init(void)
{
  unsigned int i;
  
  tracker_ctx = akbuf_new_ctx();
  num_peers = num_torrents = num_seeders = num_leechers = 0;
  peers_mem_size = 0;
  last_period = time(NULL);
  announce_count = scrape_count = status_count = peers_count = 0;
  for (i = 0; i < PEER_HASH_SIZE; i ++) torrent_hash[i] = peer_hash[i] = NULL;
  if (cfg.tracker.sync == 1) init_sync();
#ifdef INFOHASH_RESTRICTION
  init_infohash_restriction();
#endif
}
void refresh_peer(peer_entry *peer)
{
  peer_entry *headpeer;
  
  headpeer = peer;
  headpeer->num_seeders = headpeer->num_leechers = 0;
  while (peer != NULL)
  {
    if (peer->is_seeder == 1)
    {
      num_seeders ++;
      headpeer->num_seeders ++;
    } else
    {
      num_leechers ++;
      headpeer->num_leechers ++;
    }
    peer = peer->next;
  }
}
void refresh_peers(void)
{
  unsigned int i;
  peer_entry *peer, *headpeer, *prev;
  
  num_seeders = num_leechers = 0;
  num_torrents = 0;
  for (i = 0; i < PEER_HASH_SIZE; i ++) if ((peer = headpeer = torrent_hash[i]) != NULL)
  {
    num_torrents ++;
    headpeer->num_seeders = headpeer->num_leechers = 0;
    while (peer != NULL)
    {
      time_t t;
      
      if (peer->is_seeder == 1)
      {
        num_seeders ++;
        headpeer->num_seeders ++;
      } else
      {
        num_leechers ++;
        headpeer->num_leechers ++;
      }
      prev = peer;
      peer = peer->next;
      t = time(NULL) - prev->last_active;
      if ((prev->lastevent != EVENT_STOPPED && t >= cfg.tracker.timeout) || (prev->lastevent == EVENT_STOPPED && t >= cfg.tracker.stopped_timeout))
      {
        peer_del(prev);
      }
    }  
  }
}

/*
 * GET /peers?[reset]
 * reset: reset ul/dl
 */
void tracker_serve_peers(int fd, http_fd_entry *http_ent, net_fd_entry *net_ent)
{
  unsigned int i;
  peer_entry *peer;
  unsigned int do_reset, only_stopped;

  peers_count ++;
        
  /*
   * [info hash]:[ip]:[uploaded]:[downloaded]:[last event]\n
   */
  do_reset = (akbuf_table_entry_get(http_ent->args, "reset") != NULL)? 1 : 0;
  only_stopped = (akbuf_table_entry_get(http_ent->args, "stopped") != NULL)? 1 : 0;
  tracker_http_response(fd, http_ent, net_ent, HTTP_OK, "text/plain");
  for (i = 0; i < PEER_HASH_SIZE; i ++) if ((peer = torrent_hash[i]) != NULL)
  {
    while (peer != NULL)
    {
      if (only_stopped == 0 || peer->lastevent == EVENT_STOPPED)
      {
        akbuf_urlencode_data(peer->info_hash, ID_LEN, net_ent->sendbuf);
        akbuf_append_byte(net_ent->sendbuf, ':');
        akbuf_appendf(net_ent->sendbuf, "%s:%llu:%llu:", peer->ipstr, peer->uploaded, peer->downloaded);
        akbuf_appendf(net_ent->sendbuf, "%u", peer->lastevent);
        akbuf_append_byte(net_ent->sendbuf, '\n');
        if (do_reset == 1) peer->uploaded = peer->downloaded = peer->prev_uploaded = peer->prev_downloaded = 0;
      }
      peer = peer->next;
    }
  }
}
void serve_status_raw(int fd, http_fd_entry *http_ent, net_fd_entry *net_ent)
{
  unsigned int i, do_reset;
  peer_entry *peer;
  
  /*
   * [info hash]:[num seeders]:[num leechers]:[times completed]:[unixtime of last activity]\n
   * ...repeat ad nauseam...
   * the info hash is ID_LEN bytes raw data, the rest are unsigned base10 ints
   */
  tracker_http_response(fd, http_ent, net_ent, HTTP_OK, "text/plain");
  do_reset = (akbuf_table_entry_get(http_ent->args, "reset") != NULL)? 1 : 0;
  for (i = 0; i < PEER_HASH_SIZE; i ++) if ((peer = torrent_hash[i]) != NULL)
  {
    akbuf_urlencode_data(peer->info_hash, ID_LEN, net_ent->sendbuf);
    akbuf_append_byte(net_ent->sendbuf, ':');
    akbuf_appendf(net_ent->sendbuf, "%u:%u:%u:", peer->num_seeders, peer->num_leechers, peer->times_completed);
    if (do_reset == 1) peer->times_completed = 0;
    akbuf_appendf(net_ent->sendbuf, "%u", (unsigned int)peer->last_active);
    akbuf_append_byte(net_ent->sendbuf, '\n');
  }
}
void serve_status_html(int fd, http_fd_entry *http_ent, net_fd_entry *net_ent)
{
  tracker_http_response(fd, http_ent, net_ent, HTTP_OK, "text/html");
  akbuf_appendf(net_ent->sendbuf,
    "<HTML>\n"
    "<HEAD><TITLE>Hypercube tracker status</TITLE></HEAD>\n"
    "<BODY>\n"
    "<TABLE BORDER=0>\n"
    "<TR><TD>Statistics</TD><TD>&nbsp;</TD><TD>&nbsp;</TD></TR>\n"
    "<TR><TD>&nbsp;</TD><TD>Number of peers/seeders/leechers</TD><TD>%u/%u/%u</TD></TR>\n"
    "<TR><TD>&nbsp;</TD><TD>Number of torrents</TD><TD>%u</TD></TR>\n"
    "<TR><TD>&nbsp;</TD><TD>Number of announce/scrape/status/peers</TD><TD>%u/%u/%u/%u in %u sec(s)</TD></TR>\n"
    "<TR><TD>Tracker info</TD><TD>&nbsp;</TD><TD>&nbsp;</TD></TR>\n"
    "<TR><TD>&nbsp;</TD><TD>Version</TD><TD>" SERVER_VERSION "</TD></TR>\n"
    "<TR><TD>&nbsp;</TD><TD>Peer hash table buckets/size</TD><TD>0x%x/%u byte(s)</TD></TR>\n"
    "<TR><TD>&nbsp;</TD><TD>Size of peers in memory</TD><TD>%u byte(s)</TD></TR>\n",
    num_peers, num_seeders, num_leechers,
    num_torrents,
    announce_count, scrape_count, status_count, peers_count, (unsigned int)(time(NULL) - last_period),
    PEER_HASH_SIZE, sizeof(torrent_hash),
    peers_mem_size);
  if (akbuf_table_entry_get(http_ent->args, "rate") != NULL)
  {
    unsigned long long total_rate, cur_rate;
    unsigned int i;
    peer_entry *peer;
        
    total_rate = 0;
    for (i = 0; i < PEER_HASH_SIZE; i ++) if ((peer = torrent_hash[i]) != NULL)
    {
      while (peer != NULL)
      {
        unsigned long long delta;
        
        if (peer->lastevent != EVENT_STARTED && peer->lastevent != EVENT_STOPPED && peer->lastevent != EVENT_COMPLETED && peer->prev_active != (time_t)0 && peer->last_active != (time_t)0)
        {
          delta = peer->last_active - peer->prev_active;
          if (delta != 0 && peer->uploaded != 0 && peer->prev_uploaded != 0 && peer->downloaded != 0 && peer->prev_downloaded != 0 && peer->uploaded > peer->prev_uploaded && peer->downloaded > peer->prev_downloaded)
          {
            cur_rate = (peer->uploaded - peer->prev_uploaded + peer->downloaded - peer->prev_downloaded) / delta;
            if (cur_rate < 10485760) total_rate += cur_rate;
          }
        }
        peer = peer->next;
      }
    }
    total_rate /= 1048576;
    akbuf_appendf(net_ent->sendbuf, "<TR><TD>&nbsp;</TD><TD>Total rate (MB/sec)</TD><TD>%llu</TD></TR>\n", total_rate);
  }
  if (akbuf_table_entry_get(http_ent->args, "show_torrents") != NULL)
  {
    akbuf_ctxh ctx;
    akbuf *buf;
    unsigned int i;
    peer_entry *peer;

    ctx = akbuf_new_ctx();
    buf = akbuf_init(ctx, 0);
    
    akbuf_appendf(net_ent->sendbuf,
      "<TR><TD>Torrents</TD><TD><A HREF=\"?\">Hide</A></TD><TD>&nbsp;</TD></TR>\n");
    for (i = 0; i < PEER_HASH_SIZE; i ++) if ((peer = torrent_hash[i]) != NULL)
    {
      akbuf_set_idx(buf, 0);
      akbuf_urlencode_data(peer->info_hash, ID_LEN, buf);
      akbuf_asciiz(buf);
      DEBUGF("html urlenc: last byte %.2x str [%s]", peer->info_hash[ID_LEN - 1], akbuf_data(buf));
      akbuf_appendf(net_ent->sendbuf,
        "<TR><TD>&nbsp;</TD><TD>Info hash</TD><TD>%s</TD></TR>\n"
        "<TR><TD>&nbsp;</TD><TD>Seeders/Leechers/Completed</TD><TD>%u/%u/%u</TD></TR>\n"
        "<TR><TD>&nbsp;</TD><TD>Last activity</TD><TD>%s</TD></TR>\n"
        "<TR><TD>&nbsp;</TD><TD>Peer hash bucket #</TD><TD>0x%x</TD></TR>\n"
        "<TR><TD>&nbsp;</TD><TD>-------------------------------</TD><TD>&nbsp;</TD></TR>\n",
        akbuf_data(buf),
        peer->num_seeders, peer->num_leechers, peer->times_completed, 
        get_date_str(peer->last_active),
        peer->hash_idx);
    }
    akbuf_free_ctx(ctx);
  } else
  {
    akbuf_appendf(net_ent->sendbuf, "<TR><TD>Torrents</TD><TD><A HREF=\"?show_torrents=1\">Show</A></TD><TD>&nbsp;</TD></TR>\n");
  }
  akbuf_appendf(net_ent->sendbuf, "</TABLE>\n</BODY>\n</HTML>\n");

}
/*
 * GET /status?[rate]|[[norefresh]&[raw]&[reset]]
 * norefresh: don't refresh peers list
 * raw: raw format
 * reset: reset completed
 */ 
void tracker_serve_status(int fd, http_fd_entry *http_ent, net_fd_entry *net_ent)
{
  
  status_count ++;
  
  if (cfg.tracker.sync == 1) do_sync();
  
  if (akbuf_table_entry_get(http_ent->args, "norefresh") == NULL) refresh_peers();
  if (akbuf_table_entry_get(http_ent->args, "raw") != NULL)
  {
    serve_status_raw(fd, http_ent, net_ent);
  } else
  {
    serve_status_html(fd, http_ent, net_ent);
  }
}
void scrape_out(peer_entry *peer, akbuf *outbuf)
{
  akbuf_ctxh ctx;
  akbuf *buf;

  refresh_peer(peer);
  ctx = akbuf_new_ctx();
  buf = akbuf_init(ctx, 0);
  benc_raw(outbuf, peer->info_hash, ID_LEN);
  benc_key_int(buf, "complete", peer->num_seeders);
  benc_key_int(buf, "downloaded", peer->times_completed);
  benc_key_int(buf, "incomplete", peer->num_leechers);
  benc_out_dict(buf, outbuf);
  akbuf_free_ctx(ctx);
}
void tracker_serve_scrape(int fd, http_fd_entry *http_ent, net_fd_entry *net_ent)
{
  akbuf_ctxh ctx;
  akbuf *info_hash;
  akbuf *outbuf, *filesbuf, *buf;
  peer_entry *peer;
  unsigned int i;
  
#define SCRAPE_ERR(msg)\
  {\
    benc_key(outbuf, "failure reason", (msg));\
    tracker_benc_response(fd, http_ent, net_ent, outbuf);\
    akbuf_free_ctx(ctx);\
    return;\
  }

  scrape_count ++;
  
  ctx = akbuf_new_ctx();
  outbuf = akbuf_init(ctx, 0);
  filesbuf = akbuf_init(ctx, 0);
  buf = akbuf_init(ctx, 0);
  if ((info_hash = akbuf_table_entry_get(http_ent->args, "info_hash")) == NULL)
  {
    for (i = 0; i < PEER_HASH_SIZE; i ++) if ((peer = torrent_hash[i]) != NULL)
    {
      akbuf_set_idx(buf, 0);
      scrape_out(peer, filesbuf);
      peer = peer->next;
    }
  } else
  {
    if (akbuf_idx(info_hash) != ID_LEN) SCRAPE_ERR("invalid info_hash");
    if ((peer = torrent_hash[PEER_HASH_FN(info_hash)]) != NULL)
    {
      /* XXX hash colls */
      akbuf_set_idx(buf, 0);
      scrape_out(peer, filesbuf);
    }
  }
  benc_str(outbuf, "files");
  benc_out_dict(filesbuf, outbuf);
  tracker_benc_response(fd, http_ent, net_ent, outbuf);
  akbuf_free_ctx(ctx);
}
void tracker_serve_announce(int fd, http_fd_entry *http_ent, net_fd_entry *net_ent)
{
  akbuf_ctxh ctx;
  akbuf *outbuf, *peerbuf, *peersbuf;
  akbuf *info_hash, *peer_id, *ipbuf, *portbuf, *ulbuf, *dlbuf, *leftbuf, *eventbuf;
  akbuf *uabuf;
  int i;
  unsigned int j, c;
  unsigned int curevent, do_compact, only_telia;
  peer_entry *curpeer;
  struct in_addr ipaddr;
  
#define AN_ERR(msg)\
  {\
    akbuf_set_idx(outbuf, 0);\
    benc_key(outbuf, "failure reason", (msg));\
    tracker_benc_response(fd, http_ent, net_ent, outbuf);\
    akbuf_free_ctx(ctx);\
    return;\
  }
    
  announce_count ++;
  
  DEBUGF("tracker: doing announce");
  ctx = akbuf_new_ctx();
  outbuf = akbuf_init(ctx, 0);
  //benc_key_int(outbuf, "interval", cfg.tracker.interval);
  
  if ((info_hash = akbuf_table_entry_get(http_ent->args, "info_hash")) == NULL) AN_ERR("need info_hash");
#ifdef INFOHASH_RESTRICTION
  if (infohash_allowed[PEER_HASH_FN(info_hash)] == 0) AN_ERR("this tracker is for torrents on TPB only");
#endif  
  if ((peer_id = akbuf_table_entry_get(http_ent->args, "peer_id")) == NULL) AN_ERR("need peer_id");
  if ((portbuf = akbuf_table_entry_get(http_ent->args, "port")) == NULL) AN_ERR("need port");
  if ((ulbuf = akbuf_table_entry_get(http_ent->args, "uploaded")) == NULL) AN_ERR("need uploaded");
  if ((dlbuf = akbuf_table_entry_get(http_ent->args, "downloaded")) == NULL) AN_ERR("need downloaded");
  if ((leftbuf = akbuf_table_entry_get(http_ent->args, "left")) == NULL) AN_ERR("need left");
  ipbuf = akbuf_table_entry_get(http_ent->args, "ip");

  eventbuf = akbuf_table_entry_get(http_ent->args, "event");
  curevent = EVENT_NONE;
  if (eventbuf != NULL && akbuf_idx(eventbuf) > 0)
  {
    akbuf_asciiz(eventbuf);
    if (strncasecmp(akbuf_data(eventbuf), "sta", 3) == 0) curevent = EVENT_STARTED;
    else if (strncasecmp(akbuf_data(eventbuf), "com", 3) == 0) curevent = EVENT_COMPLETED;
    else if (strncasecmp(akbuf_data(eventbuf), "sto", 3) == 0) curevent = EVENT_STOPPED;
  }
  if (curevent != EVENT_NONE) DEBUGF("got event %u", curevent);
  if (akbuf_idx(info_hash) != ID_LEN || akbuf_idx(peer_id) != ID_LEN) AN_ERR("invalid info_hash and/or peer_id");
  
  do_compact = (akbuf_table_entry_get(http_ent->args, "compact") != NULL)? 1 : 0;
  only_telia = (akbuf_table_entry_get(http_ent->args, "telia") != NULL)? 1 : 0;
  
  if (curevent == EVENT_STOPPED || curevent == EVENT_COMPLETED)
  {
    if ((curpeer = peer_get(peer_id, info_hash, 0)) == NULL)
    {
      DEBUGF("event %u for unknown peer, ignoring", curevent);
      benc_str(outbuf, "peers");
      akbuf_appendf(outbuf, "le");
      tracker_benc_response(fd, http_ent, net_ent, outbuf);
      akbuf_free_ctx(ctx);
      return;
    }
  } else
  {
    if ((curpeer = peer_get(peer_id, info_hash, 1)) == NULL) AN_ERR("too many peers");
  }
  if (curevent == EVENT_STARTED || curpeer->lastevent == EVENT_STARTED)
  {
    benc_key_int(outbuf, "interval", cfg.tracker.init_interval);
  } else
  {
    benc_key_int(outbuf, "interval", cfg.tracker.interval);
  }
  curpeer->is_local = 1;
  j = 0;
  for (i = 0; i < akbuf_idx(portbuf); i ++)
  {
    akbuf_get_byte(portbuf, i, c);
    if (c < '0' || c > '9') break;
    j *= 10;
    j += c - '0';
  }
  /* causes problems for some clients if (j > 0xffff || j < 0x400) AN_ERR("invalid port"); */
  curpeer->port = j;

  if (ipbuf != NULL && akbuf_idx(ipbuf) > 1)
  {
    akbuf_asciiz(ipbuf);
    if ((ipaddr.s_addr = inet_addr(akbuf_data(ipbuf))) == INADDR_NONE)
    {
      ipbuf = NULL;
    } else
    {
      j = ntohl(ipaddr.s_addr);
      if ((j >= 0x0a000000 && j <= 0x0affffff) ||
          (j >= 0xac100000 && j <= 0xac1fffff) ||
          (j >= 0xc0a80000 && j <= 0xc0a8ffff)) ipbuf = NULL;
    }
  }
  if (ipbuf == NULL || akbuf_idx(ipbuf) <= 1)
  {
    ipbuf = akbuf_init(ctx, 0);
    akbuf_clone(ipbuf, net_ent->peerbuf);
    if ((i = akbuf_chr(ipbuf, ':')) != -1) akbuf_set_idx(ipbuf, i);
  }
  akbuf_asciiz(ipbuf);
  AKstrcpy(curpeer->ipstr, akbuf_data(ipbuf));
  j = curpeer->ipnum = ntohl(inet_addr(curpeer->ipstr));
  curpeer->ipraw[0] = (j >> 24) & 0xff;
  curpeer->ipraw[1] = (j >> 16) & 0xff;
  curpeer->ipraw[2] = (j >> 8) & 0xff;
  curpeer->ipraw[3] = j & 0xff;

  curpeer->prev_active = curpeer->last_active;
  curpeer->last_active = time(NULL);
  
#if 0
  if (num_peers == 1000000)
  {
    FILE *f;

    if (cfg.tracker.statslog != NULL && (f = fopen(cfg.tracker.statslog, "a+")) != NULL)
    {
      fprintf(f, "!!! Reached 1 million peers @ %s: %s %u\n", get_now_date_str(), curpeer->ipstr, curpeer->port);
      fflush(f);
      fclose(f);
    }
  }
#endif

  j = 0;
  for (i = 0; i < akbuf_idx(leftbuf); i ++)
  {
    akbuf_get_byte(leftbuf, i, c);
    if (c < '0' || c > '9') break;
    if (j >= 0x19999999) { j = (unsigned int)-1; break; }
    j *= 10;
    j += c - '0';
  }
  DEBUGF("got left %u", j);
  curpeer->is_seeder = (j == 0)? 1 : 0;

  curpeer->prev_uploaded = curpeer->uploaded;
  curpeer->uploaded = 0;
  for (i = 0; i < akbuf_idx(ulbuf); i ++)
  {
    akbuf_get_byte(ulbuf, i, c);
    if (c < '0' || c > '9') break;
    curpeer->uploaded *= 10;
    curpeer->uploaded += c - '0';
  }
  curpeer->prev_downloaded = curpeer->downloaded;
  curpeer->downloaded = 0;
  for (i = 0; i < akbuf_idx(dlbuf); i ++)
  {
    akbuf_get_byte(dlbuf, i, c);
    if (c < '0' || c > '9') break;
    curpeer->downloaded *= 10;
    curpeer->downloaded += c - '0';
  }
  DEBUGF("ul %llu dl %llu", curpeer->uploaded, curpeer->downloaded);
  
  curpeer->lastevent = curevent;

  if ((uabuf = akbuf_table_entry_get(http_ent->headers, "User-Agent")) != NULL)
  {
    if (akbuf_idx(uabuf) >= 12 && memcmp(akbuf_data(uabuf), "Ratio Fucker", 12) == 0)
    {
      akbuf_asciiz(net_ent->peerbuf);
      aklogf(LOG_INFO, "Cheater: Ratio Fucker request from %s", akbuf_data(net_ent->peerbuf));
      curpeer->uploaded = 0;
      curpeer->downloaded = 0;
    }
  }
  
  i = 0;
  peerbuf = akbuf_init(ctx, 0);
  peersbuf = akbuf_init(ctx, 0);
  
  if (curevent == EVENT_COMPLETED)
  {
    torrent_hash[curpeer->hash_idx]->times_completed ++;
    curpeer->is_complete = 1;
  }
  send_peers(peersbuf, curpeer, (curpeer->is_seeder == 1)? 0 : 1, do_compact, only_telia);
  if (do_compact == 1)
  {
    benc_key_buf(outbuf, "peers", peersbuf);
  } else
  {
    benc_str(outbuf, "peers");
    benc_out_list(peersbuf, outbuf);
  }
  tracker_benc_response(fd, http_ent, net_ent, outbuf);
  if (curevent != EVENT_STOPPED && cfg.tracker.sync == 1) sync_peer(curpeer);
  
  akbuf_free_ctx(ctx);
}
void update_stats(void)
{
#ifdef WITH_MYSQL
  MYSQL sql_conn;
  akbuf *buf, *sqlbuf;
  akbuf_ctxh ctx;
  unsigned int i;
  peer_entry *peer, *headpeer;
    
  if (cfg.tracker.sql_stats == 0) return;
  DEBUGF("doing update_stats()");
  if (fork() != 0) return;
  
  signal(SIGALRM, exit);
  alarm(cfg.tracker.period);
  DEBUGF("in update_stats() child");
  //while (1) sleep(1);
  mysql_init(&sql_conn);
  if (mysql_real_connect(&sql_conn, cfg.tracker.sql_host, cfg.tracker.sql_user, cfg.tracker.sql_pass, cfg.tracker.sql_db, 0, NULL, 0) == NULL)
  {
    aklogf(LOG_ERROR, "Couldn't connect to MySQL server: %s", mysql_error(&sql_conn));
    exit(1);
  }
  ctx = akbuf_new_ctx();
  buf = akbuf_init(ctx, 0);
  sqlbuf = akbuf_init(ctx, 0);
  akbuf_sprintf(sqlbuf, "UPDATE hc_stats SET seeders='%u', leechers='%u', num_torrents='%u'", num_seeders, num_leechers, num_torrents);
  akbuf_asciiz(sqlbuf);
  DEBUGF("sql query (hc_stats) [%s]", akbuf_data(sqlbuf));
  if (mysql_real_query(&sql_conn, akbuf_data(sqlbuf), akbuf_idx(sqlbuf)) != 0)
  {
      DEBUGF("SQL UPDATE query failed: %s", mysql_error(&sql_conn));
  }
  for (i = 0; i < PEER_HASH_SIZE; i ++) if ((peer = headpeer = torrent_hash[i]) != NULL)
  {
    akbuf_set_idx(buf, 0);
    akbuf_set_idx(sqlbuf, 0);
    akbuf_base64encode_data(peer->info_hash, ID_LEN, buf);
    akbuf_asciiz(buf);
    akbuf_sprintf(sqlbuf, "UPDATE torrents SET seeders='%u', leechers='%u', last_active='%u' WHERE info_hash='%s'", peer->num_seeders, peer->num_leechers, peer->last_active, akbuf_data(buf));
    akbuf_asciiz(sqlbuf);
    DEBUGF("sql query (torrents) [%s]", akbuf_data(sqlbuf));
    if (mysql_real_query(&sql_conn, akbuf_data(sqlbuf), akbuf_idx(sqlbuf)) != 0)
    {
      DEBUGF("SQL UPDATE query failed: %s", mysql_error(&sql_conn));
    }
    while (peer != NULL)
    {
      if (peer->is_complete == 1)
      {
        peer->is_complete = 0;
        akbuf_set_idx(buf, 0);
        akbuf_set_idx(sqlbuf, 0);
        akbuf_base64encode_data(peer->info_hash, ID_LEN, buf);
        akbuf_asciiz(buf);
        akbuf_sprintf(sqlbuf, "UPDATE torrents SET num_downloads=num_downloads+1 WHERE info_hash='%s'", akbuf_data(buf));
        akbuf_asciiz(sqlbuf);
        DEBUGF("sql query (torrents complete) [%s]", akbuf_data(sqlbuf));
        if (mysql_real_query(&sql_conn, akbuf_data(sqlbuf), akbuf_idx(sqlbuf)) != 0)
        {
          DEBUGF("SQL UPDATE query failed: %s", mysql_error(&sql_conn));
        }
      } else if (peer->lastevent == EVENT_STOPPED)
      {
        akbuf_set_idx(buf, 0);
        akbuf_set_idx(sqlbuf, 0);
        akbuf_base64encode_data(peer->info_hash, ID_LEN, buf);
        akbuf_asciiz(buf);
        akbuf_sprintf(sqlbuf, "UPDATE users SET uploaded=uploaded+'%llu', downloaded=downloaded+'%llu' WHERE ip='%u'", peer->uploaded, peer->downloaded, peer->ipnum); 
        akbuf_asciiz(sqlbuf);
        DEBUGF("sql query (peers) [%s]", akbuf_data(sqlbuf));
        if (mysql_real_query(&sql_conn, akbuf_data(sqlbuf), akbuf_idx(sqlbuf)) != 0)
        {
          DEBUGF("SQL UPDATE query failed: %s", mysql_error(&sql_conn));
        } else
        {
          peer->uploaded = peer->downloaded = 0;
          peer->prev_uploaded = peer->prev_downloaded = 0;
        }
        peer->uploaded = peer->downloaded = 0;
        peer->prev_uploaded = peer->prev_downloaded = 0;
        
      }
      peer = peer->next;
    }
  }  
  akbuf_free_ctx(ctx);
  exit(0);
#endif
}
void tracker_periodic(void)
{
  time_t t;
  FILE *f;
  
  //scramble_peers();
#ifdef INFOHASH_RESTRICTION
  if ((t = time(NULL) - last_infohash_period) >= cfg.tracker.infohash_interval) 
  {
    read_infohash_file();
    last_infohash_period = time(NULL);
  }
#endif
  if ((t = time(NULL) - last_period) < cfg.tracker.period) return;
  if (cfg.tracker.statslog != NULL && (f = fopen(cfg.tracker.statslog, "a+")) != NULL)
  { 
    fprintf(f, "%s %u %u %u %u / %u\n", get_now_date_str(), announce_count, scrape_count, status_count, peers_count, (unsigned int)t);
    fflush(f);
    fclose(f);
  }
  announce_count = scrape_count = status_count = peers_count = 0;
  refresh_peers();
  update_stats();
  last_period = time(NULL);
}
