#include "hypercube.h"

extern hypercube_config cfg;

void mainloop(void)
{
  DEBUGF("entering mainloop");
  while (1) 
  {
    net_wait_for_events();
#ifdef SOCKET_TIMEOUT
    net_periodic();
#endif
    tracker_periodic();
  }
}
void handle_fatal_sig(int sig)
{
  aklogf(LOG_ERROR, "Exiting on signal %d.", sig);
  exit(sig);
}
void handle_reload_sig(int sig)
{
  aklogf(LOG_INFO, "Got signal %d, reloading config...", sig);
  cfg_reload();
}
void final_init(void)
{
  struct stat ost, st;
  
  if (stat("/", &ost) != 0) { perror("Couldn't stat /"); exit(1); }
  if (cfg.chroot_dir != NULL && (chroot(cfg.chroot_dir) != 0 || chdir("/") != 0)) { perror("Changing root directory"); exit(1); }
  if (stat(cfg.default_root, &st) == 0)
  {
    if (st.st_ino == ost.st_ino)
    {
      fprintf(stderr, "Refusing to start with filesystem root as default root.\n");
      exit(1);
    }
  } else
  {
    fprintf(stderr, "Warning: Couldn't access default root (%s): %s\n", cfg.default_root, strerror(errno));
  }
  if (cfg.run_as_gid != -1 && setgid(cfg.run_as_gid) != 0) { perror("Changing GID"); exit(1); }
  if (cfg.run_as_uid != -1 && setuid(cfg.run_as_uid) != 0) { perror("Changing UID"); exit(1); }
  if (cfg.background == 1)
  {
    fclose(stdin); fclose(stdout); fclose(stderr);
    if (fork() != 0) exit(0);
  }
  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);
  signal(SIGTERM, handle_fatal_sig);
  signal(SIGINT, handle_fatal_sig);
  signal(SIGHUP, handle_reload_sig);
}
int main(int argc, char *argv[])
{
  cfg_init();
  log_init();
  net_init();
  http_init();
  tracker_init();
  net_start_listen();
  final_init();
  mainloop();
  return 0;
}
