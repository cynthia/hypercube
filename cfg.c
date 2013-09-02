#include "hypercube.h"

static akbuf_ctxh cfg_ctx;
FILE *cfg_f = NULL;

hypercube_config cfg;

enum { CFG_NONE, CFG_BOOL, CFG_INT, CFG_STR, CFG_TABLE, CFG_INADDR, CFG_REGEX_TABLE, CFG_FUNC };

int cfg_func_include(unsigned char *, unsigned int, unsigned char **, unsigned int);
int cfg_func_echo(unsigned char *, unsigned int, unsigned char **, unsigned int);

struct hypercube_config_token
{
  unsigned char *key;
  unsigned int type;
  void *val;
} hypercube_config_tokens[] =
{
  { "listen_port",	CFG_INT,		&cfg.listen_port	},
  { "listen_addr",	CFG_INADDR,		&cfg.listen_addr	},
  { "default_root",	CFG_STR,		&cfg.default_root	},
  { "log",		CFG_BOOL,		&cfg.log		},
  { "log_level",	CFG_STR,		&cfg.log_level		},
  { "log_file",		CFG_STR,		&cfg.log_file		},
  { "background",	CFG_BOOL,		&cfg.background		},
  { "run_as_uid",	CFG_INT,		&cfg.run_as_uid		},
  { "run_as_gid",	CFG_INT,		&cfg.run_as_gid		},
  { "chroot_dir",	CFG_STR,		&cfg.chroot_dir		},
  { "vhost",		CFG_TABLE,		&cfg.vhosts		},
  { "mime",		CFG_TABLE,		&cfg.mime_types		},
  { "rewrite",		CFG_REGEX_TABLE,	&cfg.rewrite_rules	},
  { "include",		CFG_FUNC,		cfg_func_include	},
  { "echo",		CFG_FUNC,		cfg_func_echo		},
  { "allow",		CFG_REGEX_TABLE,	&cfg.allow_clients	},
  { "deny",		CFG_REGEX_TABLE,	&cfg.deny_clients	},
  
  /* tracker */
  { "tracker_interval",		CFG_INT,		&cfg.tracker.interval		},
  { "tracker_init_interval",	CFG_INT,		&cfg.tracker.init_interval	},
  { "tracker_timeout",		CFG_INT,		&cfg.tracker.timeout		},
  { "tracker_stopped_timeout",	CFG_INT,		&cfg.tracker.stopped_timeout	},
  { "tracker_respnum",		CFG_INT,		&cfg.tracker.respnum		},
  { "tracker_period",		CFG_INT,		&cfg.tracker.period		},
  { "tracker_sql_stats",	CFG_BOOL,		&cfg.tracker.sql_stats		},
  { "tracker_sql_host",		CFG_STR,		&cfg.tracker.sql_host		},
  { "tracker_sql_db",		CFG_STR,		&cfg.tracker.sql_db		},
  { "tracker_sql_user",		CFG_STR,		&cfg.tracker.sql_user		},
  { "tracker_sql_pass",		CFG_STR,		&cfg.tracker.sql_pass		},
  { "tracker_statslog",		CFG_STR,		&cfg.tracker.statslog		},
  { "tracker_sync",		CFG_BOOL,		&cfg.tracker.sync		},
  { "tracker_sync_interval",	CFG_INT,		&cfg.tracker.sync_interval	},
  { "tracker_sync_size",	CFG_INT,		&cfg.tracker.sync_size		},
  { "tracker_sync_addr",	CFG_INADDR,		&cfg.tracker.sync_addr		},
  { "tracker_sync_port",	CFG_INT,		&cfg.tracker.sync_port		},
  { "tracker_infohash_file",	CFG_STR,		&cfg.tracker.infohash_file	},
  { "tracker_infohash_interval",CFG_INT,		&cfg.tracker.infohash_interval	},		
  { NULL,			CFG_NONE,		NULL				},
};

#define CFG_ERR_HDR() fprintf(stderr, "Error in configuration '%s' on line %u:\n  ", filename, curline);  

int cfg_load(unsigned char *filename, unsigned int level)
{
  FILE *f;
  unsigned char readbuf[BUF_SIZE], *p;
#define MAX_CFG_TOKENS 16
  unsigned char *tokenv[MAX_CFG_TOKENS];
  unsigned int tokenc, i;
  unsigned int curline;
  unsigned int bool_val;
  
  curline = 0;
  
  if (level == 0)
  {
    if (cfg_f == NULL || fseek(cfg_f, 0, SEEK_SET) != 0)
    {
      if ((f = fopen(filename, "r")) == NULL) { fprintf(stderr, "Unable to open config file '%s': %s\n", filename, strerror(errno)); return -1; }
      cfg_f = f;
    } else
    {
      f = cfg_f;
    }
  } else
  {
    if ((f = fopen(filename, "r")) == NULL) { fprintf(stderr, "Unable to open config file '%s': %s\n", filename, strerror(errno)); return -1; }
  }
  while (fgets(readbuf, sizeof(readbuf) - 1, f) != NULL)
  {
    curline ++;
    if ((p = strpbrk(readbuf, "\n\r")) != NULL) *p = 0;
    tokenc = 0;
    p = readbuf;
    while (*p == ' ' || *p == '\t') p ++;
    if (*p == '#') continue;
    bool_val = 1;
    DEBUGF("cfg line %s:%u [%s]", filename, curline, p);
    if (*p == 0) continue;
    p = strtok(p, " \t");
    while (tokenc < MAX_CFG_TOKENS && p != NULL && *p != '#')
    {
      /* handle !foo / no foo */
      if (tokenc == 0)
      {
        if (*p == '!') { bool_val = 0; p ++; }
        else if (strcasecmp(p, "no") == 0) { bool_val = 0; p = NULL; }
      }
      if (p != NULL && *p != 0) tokenv[tokenc ++] = strdup(p);
      p = strtok(NULL, " \t");
    }
    if (tokenc == 0) continue;
    for (i = 0; hypercube_config_tokens[i].key != NULL; i ++) if (strcasecmp(hypercube_config_tokens[i].key, tokenv[0]) == 0) break;
    if (hypercube_config_tokens[i].key == NULL) { CFG_ERR_HDR(); fprintf(stderr, "Unknown key '%s'\n", tokenv[0]); return -1; }
    if (hypercube_config_tokens[i].type == CFG_BOOL)
    {
      if (tokenc != 1) { CFG_ERR_HDR(); fprintf(stderr, "Invalid number of arguments (expected [!]%s)\n", tokenv[0]); return -1; }
      DEBUGF("bool value '%s' = %u", hypercube_config_tokens[i].key, bool_val);
      *(int *)hypercube_config_tokens[i].val = bool_val;
    } else if (bool_val != 0) switch (hypercube_config_tokens[i].type)
    {
      case CFG_NONE: break;
      case CFG_INT:
      {
        if (tokenc != 2) { CFG_ERR_HDR(); fprintf(stderr, "Invalid number of arguments (expected %s <number>)\n", tokenv[0]); return -1; }
        *(int *)hypercube_config_tokens[i].val = atoi(tokenv[1]);
        break;
      }
      case CFG_STR:
      {
        unsigned char **dest;
        
        if (tokenc != 2) { CFG_ERR_HDR(); fprintf(stderr, "Invalid number of arguments (expected %s <string>)\n", tokenv[0]); return -1; }
        dest = hypercube_config_tokens[i].val;
        *dest = strdup(tokenv[1]);
        break;
      }
      case CFG_TABLE:
      {
        akbuf_table *tbl;
        unsigned char **dest;
        
        if (tokenc != 3) { CFG_ERR_HDR(); fprintf(stderr, "Invalid number of arguments (expected %s <key> <value>)\n", tokenv[0]); return -1; }
        dest = hypercube_config_tokens[i].val;
        tbl = (akbuf_table *)*dest;
        akbuf_table_entry_add_str(cfg_ctx, tbl, tokenv[1], tokenv[2]);
        break;
      }
      case CFG_REGEX_TABLE:
      {
        akbuf_table *tbl;
        unsigned char **dest;
        akbuf *compbuf, *valbuf;
        int ret;
        
        if (tokenc != 2 && tokenc != 3) { CFG_ERR_HDR(); fprintf(stderr, "Invalid number of arguments (expected %s <regex> [arg])\n", tokenv[0]); return -1; }
        compbuf = akbuf_init(cfg_ctx, sizeof(regex_t));
        if ((ret = regcomp((regex_t *)akbuf_data(compbuf), tokenv[1], REG_EXTENDED)) != 0)
        {
          unsigned char errbuf[BUF_SIZE];
          
          regerror(ret, (regex_t *)akbuf_data(compbuf), errbuf, sizeof(errbuf));
          fprintf(stderr, "Parsing of regex '%s' failed: %s\n", tokenv[1], errbuf);
          return -1;
        }
        akbuf_set_idx(compbuf, sizeof(regex_t));
        valbuf = akbuf_init(cfg_ctx, 0);
        akbuf_strcpy(valbuf, tokenv[2]);
        dest = hypercube_config_tokens[i].val;
        tbl = (akbuf_table *)*dest;
        akbuf_table_entry_add_buf(cfg_ctx, tbl, compbuf, valbuf);
        akbuf_free(cfg_ctx, valbuf);
        break;
      }
      case CFG_INADDR:
      {
        struct in_addr *addr;
        
        if (tokenc != 2) { CFG_ERR_HDR(); fprintf(stderr, "Invalid number of arguments (expected %s <IP address>)\n", tokenv[0]); return -1; }
        addr = hypercube_config_tokens[i].val;
        if ((addr->s_addr = inet_addr(tokenv[1])) == -1) { CFG_ERR_HDR(); fprintf(stderr, "Invalid IP address '%s'\n", tokenv[1]); return -1; }
        break;
      }
      case CFG_FUNC:
      {
        int (*func)();
        func = hypercube_config_tokens[i].val;
        if (func != NULL) if (func(filename, curline, tokenv, tokenc) != 0) return -1;
        break;
      }
    }
  }
  return 0;
}

int cfg_func_include(unsigned char *filename, unsigned int curline, unsigned char **tokenv, unsigned int tokenc)
{
  if (tokenc != 2)
  {
    CFG_ERR_HDR();
    fprintf(stderr, "Invalid number of arguments (expected %s <filename>)\n", tokenv[0]);
    return -1;
  }
  return cfg_load(tokenv[1], 1);
}
int cfg_func_echo(unsigned char *filename, unsigned int curline, unsigned char **tokenv, unsigned int tokenc)
{
  unsigned char *msg;
  
  if (tokenc < 2) msg = ""; else msg = tokenv[1];
  printf("%s:%u: %s\n", filename, curline, msg);
  return 0;
}

void cfg_init(void)
{
  cfg_ctx = akbuf_new_ctx();
  cfg.listen_port = 8000;
  cfg.listen_addr.s_addr = INADDR_ANY;
  cfg.default_root = "dox/";
  cfg.log = 1;
  cfg.log_level = "request";
  cfg.log_file = NULL;
  cfg.background = 0;
  cfg.run_as_uid = cfg.run_as_gid = -1;
  cfg.chroot_dir = NULL;
  cfg.tracker.statslog = NULL;
  
  cfg.vhosts = akbuf_table_init(cfg_ctx, AKBUF_TABLE_NOCASE);
  cfg.mime_types = akbuf_table_init(cfg_ctx, AKBUF_TABLE_NOCASE);
  cfg.rewrite_rules = akbuf_table_init(cfg_ctx, AKBUF_TABLE_BIN);
  cfg.allow_clients = akbuf_table_init(cfg_ctx, AKBUF_TABLE_BIN);
  cfg.deny_clients = akbuf_table_init(cfg_ctx, AKBUF_TABLE_BIN);
  
  /* tracker */
  cfg.tracker.interval = 360;
  cfg.tracker.timeout = 360 * 2;
  cfg.tracker.stopped_timeout = 300 * 2;
  cfg.tracker.respnum = 50;
  cfg.tracker.period = 15;
  cfg.tracker.sql_stats = 0;
  cfg.tracker.sql_host = NULL;
  cfg.tracker.sql_db = NULL;
  cfg.tracker.sql_user = NULL;
  cfg.tracker.sql_pass = NULL;
  cfg.tracker.sync = 0;
  cfg.tracker.sync_interval = 15;
  cfg.tracker.sync_size = 1400;
  cfg.tracker.sync_addr.s_addr = INADDR_BROADCAST;
  cfg.tracker.sync_port = 4242;
  cfg.tracker.infohash_file = NULL;
  cfg.tracker.infohash_interval = 30;

  if (cfg_load(CFG_FILE, 0) != 0) exit(1);
}

void cfg_reload(void)
{
  akbuf_free_ctx(cfg_ctx);
  cfg_init();
}
