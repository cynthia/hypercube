#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <limits.h>
#include <signal.h>
#include <dirent.h>
#include <regex.h>

#ifdef WITH_MYSQL
#include <mysql/mysql.h>
#endif

#include "dist.h"
#include "config.h"
#include "akbuf/akbuf.h"
#include "asio/asio.h"

#ifdef USE_LINUX_SENDFILE
#include <sys/sendfile.h>
#endif

#include "log.h"
#include "net.h"
#include "http.h"
#include "cfg.h"
#include "tracker.h"

#ifdef DEBUG
#define DEBUGF(v...) aklogf(LOG_DEBUG, "DEBUG: " v);
#define AKdassert(cond) AKassert(cond)
#else
#define DEBUGF(v...)
#define AKdassert(cond)
#endif

#define AKassert(c) if (!(c)) { aklogf(LOG_ERROR, "Assertion (" __STRING(c) ") failed @ " __FILE__ ":%u", __LINE__); exit(1); }
#define AKstrcpy(dest, src) { strncpy((dest), (src), sizeof(dest) - 1); (dest)[sizeof(dest) - 1] = 0; }

#ifdef SHORT_SERVER_VERSION
#define SERVER_VERSION_STR	"hypercube"
#else
#define SERVER_VERSION_STR	"hypercube/1.1alpha tracker/0.1alpha (" SERVER_DIST ") by anakata [anakata-hc@prq.se]"
#endif

#ifdef DEBUG
#define SERVER_VERSION		SERVER_VERSION_STR " [debug build]"
#else
#define SERVER_VERSION		SERVER_VERSION_STR
#endif
