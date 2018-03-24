#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>

#include "include/mssl.h"
#include "include/config.h"
#include "include/logs.h"
#include "include/tcp_in.h"
#include "include/util.h"

int8_t end_app_exists = 0;
int8_t mon_app_exists = 0;
char *file = NULL;

#define MATCH_ITEM(name, item) \
  ((strncmp(#name, item, strlen(#name)) == 0) \
   && (!isalnum(item[strlen(#name)])))

#define TRY_ASSIGN_NUM(name, base, item, value) \
  ((strncmp(#name, item, strlen(#name)) == 0) \
   && (!isalnum(item[strlen(#name)])) \
   && (sscanf(value, \
       (sizeof((base)->name) == sizeof(char)) ? "%hhi" : \
       (sizeof((base)->name) == sizeof(short)) ? "%hi" : \
       (sizeof((base)->name) == sizeof(int)) ? "%i" : \
       (sizeof((base)->name) == sizeof(long)) ? "%li" : \
       (sizeof((base)->name) == sizeof(long long)) ? "%lli" : "ERROR", \
       &(base)->name) > 0))

#define TRY_ASSIGN_STR(name, base, item, value) \
  (((strncmp(#name, item, strlen(#name)) == 0) \
    && (!isalnum(item[strlen(#name)])) \
    && (strlen(value) < sizeof((base)->name))) ? \
   (strcpy((base)->name, value), 1) : 0)

#define LINE_FOREACH(line, llen, buf, blen) \
  for (line = buf, \
      llen = ((strchr(line, '\n') == NULL) ? (buf + blen - line) \
        : strchr(line, '\n') - line); \
      line + llen < buf + blen; \
      line += llen + 1, \
      llen = ((strchr(line, '\n') == NULL) ? (buf + blen - line) \
        : strchr(line, '\n') - line)) \

static int set_multi_process_support(char *multiprocess_details)
{
  char *token = " =";
  char *sample;
  char *saveptr;

  MA_LOG("Loading multi-process configuration");

  sample = strtok_r(multiprocess_details, token, &saveptr);

  if (!sample)
  {
    MA_LOG("No option for multi-process support given");
    return -1;
  }
  g_config.mos->multiprocess_curr_core = mystrtol(sample, 10);

  sample = strtok_r(NULL, token, &saveptr);
  if ((!sample) && !strcmp(sample, "master"))
    g_config.mos->multiprocess_is_master = 1;

  return 0;
}

static int detect_word(char *buf, int len, char **word, int *wlen)
{
  int i;
  for (i=0; i<len; i++)
  {
    if (isspace(buf[i]))
      continue;

    if (isalpha(buf[i]))
    {
      *word = &buf[i];
      break;
    }
    else
      return -1;
  }

  if (i == len)
    return -1;

  for (*wlen = 0; *wlen < len; (*wlen)++)
  {
    if (isalnum((*word)[*wlen]) || (*word)[*wlen] == '_')
      continue;

    assert(*wlen != 0);
    break;
  }

  assert(*word >= buf && *word + *wlen <= buf + len);

  return 0;
}

/**
 * @brief Read the configuration file and load it on the memory
 * @param File name
 * @return Pointer to the memory
 */
static char *read_conf(const char *fname)
{
  int size;
  ssize_t have_read = 0, rc;
  FILE *fp = fopen(fname, "r");

  if (fp == NULL)
  {
    MA_LOG1s("Cannot open the config file", fname);
    exit(EXIT_FAILURE);
  }

  fseek(fp, 0L, SEEK_END);
  size = ftell(fp);
  fseek(fp, 0L, SEEK_SET);

  file = (char *)calloc(1, size + 1);
  if (file == NULL)
  {
    MA_LOG("Can't allocate memory for file!");
    exit(EXIT_FAILURE);
  }

  file[size] = '\0';

  while (have_read < size)
  {
    rc = fread(file, 1, size, fp);
    if (rc <= 0) break;
    have_read += rc;
  }

  fclose(fp);

  return file;
}

/**
 * @brief Preprocess the configurations
 * @param Memory loaded for the configurations
 * @return Pointer to the preprocessed memory
 */
static char *preprocess_conf(char *raw)
{
  char *line;
  int llen;

  int len = strlen(raw);

  LINE_FOREACH(line, llen, raw, len) 
  {
    int i, iscomment = 0;
    for (i=0;  i<llen; i++)
    {
      if (!iscomment && line[i] == '#')
        iscomment = 1;
      if (iscomment)
        line[i] = ' ';
    }
  }

  return raw;
}

static void fetch_arp_kernel_entries(struct arp_conf * const config)
{
#define _PATH_PROCNET_ARP "/proc/net/arp"
#define DPDK_PREFIX       "dpdk"
#define DPDK_PREFIX_LEN   4
#define LINE_LEN          200
#define ENTRY_LEN         25

  FILE *fp;
  char ip[ENTRY_LEN];
  char hwa[ENTRY_LEN];
  char mask[ENTRY_LEN];
  char dev[WORD_LEN];
  char line[LINE_LEN];
  int type, flags, num;

  if (!(fp = fopen(_PATH_PROCNET_ARP, "r")))
  {
    MA_LOG1s("Error", _PATH_PROCNET_ARP);
    exit(EXIT_FAILURE);
  }

  if (fgets(line, sizeof(line), fp) != (char *) NULL) 
  {
    strcpy(mask, "-");
    strcpy(dev, "-");
    
    for (; fgets(line, sizeof(line), fp);) 
    {
      num = sscanf(line, "%s 0x%x 0x%x %100s %100s %100s\n",
                            ip, &type, &flags, hwa, mask, dev);
      if (num < 6)
        break;

      if (strncmp(dev, DPDK_PREFIX, DPDK_PREFIX_LEN))
        continue;

      if (flags != 0x00) 
      {
        struct _arp_entry *ent = calloc(1, sizeof(struct _arp_entry));
        if (!ent) 
        {
          MA_LOG("Can't allocate memory for arp_entry");
          exit(EXIT_FAILURE);
        }
        uint8_t haddr[ETH_ALEN] = {0};
        if (sscanf(hwa, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
              &haddr[0], &haddr[1], &haddr[2],
              &haddr[3], &haddr[4], &haddr[5]) != 6) 
        {
          MA_LOG("Error reading the ARP entry");
          exit(EXIT_FAILURE);
        }
        ent->ip = inet_addr(ip);
        ent->prefix = 32;
        ent->mask = htonl((ent->prefix == 0) ? 0 : ((-1) << (32 - ent->prefix)));
        ent->masked_ip = ent->mask & ent->ip;
        memcpy(ent->haddr, haddr, ETH_ALEN);
        TAILQ_INSERT_TAIL(&config->list, ent, link);
        config->ent[config->num] = ent;
        config->num++;
      }
    }
  }

  fclose(fp);
}

static void fetch_route_kernel_entries(struct route_conf * const config)
{
#define	_PATH_PROCNET_ROUTE		"/proc/net/route"
#define	DPDK_PREFIX			"dpdk"
#define DPDK_PREFIX_LEN			4
	
	FILE *fp;
	uint32_t gate;
	uint32_t dest;
	uint32_t mask;
	char dev[WORD_LEN];
	char line[LINE_LEN];
	char mtu[ENTRY_LEN];
	char win[ENTRY_LEN];
	char irtt[ENTRY_LEN];
	int flags, num, cnt, use, metric;
	
	if ((fp = fopen(_PATH_PROCNET_ROUTE, "r")) == NULL) {
		MA_LOG1s("Error", _PATH_PROCNET_ARP);
		exit(EXIT_FAILURE);
	}

	/* Bypass header -- read until newline */
	if (fgets(line, sizeof(line), fp) != (char *) NULL) {
		/* Read the route table entries. */
		for (; fgets(line, sizeof(line), fp);) {

			num = sscanf(line, "%s %08X %08X %d %d %d %d %08X %s %s %s\n",
				     dev,
				     &dest,
				     &gate,
				     &flags, &cnt, &use, &metric,
				     &mask,
				     mtu, win, irtt);

			if (num < 11)
				break;
#if 0
			/* if the user specified device differs, skip it */
			if (strncmp(dev, DPDK_PREFIX, DPDK_PREFIX_LEN))
				continue;
#endif
			struct route_entry *ent = calloc(1, sizeof(struct route_entry));
			if (!ent) {
				MA_LOG("Could not allocate memory for route_entry!");
				exit(EXIT_FAILURE);
			}
			
			ent->ip = dest;

			/* __builtin_clz() returns undefined output with zero */
			if (mask == 0)
				ent->prefix = 0;
			else
				ent->prefix = 32 - __builtin_clz(mask);
			ent->mask = mask;
			ent->masked_ip = ent->mask & ent->ip;
			strcpy(ent->dev_name, dev);
			TAILQ_INSERT_TAIL(&config->list, ent, link);
			config->ent[config->num] = ent;
			config->num++;
		}
	}
	
	fclose(fp);
}

static int read_item_value(char *line, int llen, char *item, int ilen, char *value, int vlen)
{
  const char *end = &line[llen];
  char *word = NULL;
  int wlen = 0;

  if (detect_word(line, llen, &word, &wlen) < 0 || wlen > ilen)
    return -1;

  line = word + wlen;

  while (line < end && isspace(*line))
    line++;

  if (*(line++) != '=')
    return -1;

  while (line < end && isspace(*line))
    line++;

  if (end - line > vlen)
    return -1;

  while (isspace(*(end - 1)))
    end--;

  if (end <= line)
    return -1;

  strncpy(item, word, wlen);
  strncpy(value, line, (size_t)(end - line));

  return 0;
}

static void feed_app_conf_line(struct conf_block *blk, char *line, int len)
{
  struct app_conf * const conf = (struct app_conf *)blk->conf;

  char item[WORD_LEN + 1] = {0};
  char value[STR_LEN + 1] = {0};

  if (read_item_value(line, len, item, WORD_LEN, value, STR_LEN) < 0)
    return;

  if (TRY_ASSIGN_STR(type, conf, item, value));
  else if (TRY_ASSIGN_STR(run, conf, item, value))
  {
    str_to_args(conf->run, &conf->app_argc, conf->app_argv, MOS_APP_ARGC);
  }
  else if (TRY_ASSIGN_NUM(cpu_mask, conf, item, value));
  else if (TRY_ASSIGN_NUM(ip_forward, conf, item, value));
}

static void feed_mos_conf_line(struct conf_block *blk, char *line, int len)
{
  struct mos_conf * const conf = (struct mos_conf *)blk->conf;

  char item[WORD_LEN + 1] = {0};
  char value[STR_LEN + 1] = {0};

  if (read_item_value(line, len, item, WORD_LEN, value, STR_LEN) < 0)
    return;

  if (TRY_ASSIGN_NUM(nb_mem_channels, conf, item, value));
  else if (TRY_ASSIGN_NUM(forward, conf, item, value));
  else if (TRY_ASSIGN_NUM(max_concurrency, conf, item, value));
  else if (TRY_ASSIGN_NUM(clnt_rmem_size, conf, item, value));
  else if (TRY_ASSIGN_NUM(clnt_wmem_size, conf, item, value));
  else if (TRY_ASSIGN_NUM(serv_rmem_size, conf, item, value));
  else if (TRY_ASSIGN_NUM(serv_wmem_size, conf, item, value));
  else if (TRY_ASSIGN_NUM(tcp_tw_interval, conf, item, value))
    g_config.mos->tcp_tw_interval = 
      SEC_TO_USEC(g_config.mos->tcp_tw_interval) / TIME_TICK;
  else if (TRY_ASSIGN_NUM(no_ring_buffers, conf, item, value));
  else if (TRY_ASSIGN_STR(mos_log, conf, item, value));
  else if (TRY_ASSIGN_STR(stat_print, conf, item, value));
  else if (TRY_ASSIGN_STR(port, conf, item, value));
  else if (strcmp(item, "multiprocess") == 0)
  {
    conf->multiprocess = 1;
    set_multi_process_support(value);
  }
}

static void feed_netdev_conf_line(struct conf_block *blk, char *line, int len)
{
  MA_LOG("feed_netdev_conf_line");
  struct netdev_conf * const conf = (struct netdev_conf *)blk->conf;

#ifndef DARWIN
  int i;
#endif
  uint64_t cpu_mask;
  char *word = NULL;
  int wlen;

  if (detect_word(line, len, &word, &wlen) < 0 || wlen > WORD_LEN || wlen <= 0)
    return;

  line = word + wlen;

  if (sscanf(line, "%li", &cpu_mask) <= 0)
    return;

  struct netdev_entry *ent = calloc(1, sizeof(struct netdev_entry));

  if (!ent)
  {
    MA_LOG("Could not allocate memory for netdev_entry");
    exit(EXIT_FAILURE);
  }

  strncpy(ent->dev_name, word, wlen);
  ent->cpu_mask = cpu_mask;
  g_config.mos->cpu_mask |= cpu_mask;

  strncpy(ent->ifr.ifr_name, ent->dev_name, IFNAMSIZ-1);
  ent->ifr.ifr_name[IFNAMSIZ-1] = '\0';

  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sock < 0)
  {
    MA_LOG("socket");
    exit(EXIT_FAILURE);
  }

  if (ioctl(sock, SIOCGIFADDR, &ent->ifr) == 0)
  {
    struct in_addr sin = ((struct sockaddr_in *) &ent->ifr.ifr_addr)->sin_addr;
    ent->ip_addr = *(uint32_t *)&sin;
  }

  if (ioctl(sock, SIOCGIFNETMASK, &ent->ifr) == 0)
  {
    struct in_addr sin = ((struct sockaddr_in *)&ent->ifr.ifr_addr)->sin_addr;
    ent->netmask = *(uint32_t *)&sin;
  }

#ifdef DARWIN
#else
  if (ioctl(sock, SIOCGIFHWADDR, &ent->ifr) == 0)
  {
    for (i=0; i<6; i++)
    {
      ent->haddr[i] = ent->ifr.ifr_addr.sa_data[i];
    }
  }
#endif
  MA_LOG2s("MAC addr", ent->haddr, 6);

  close(sock);

  ent->ifindex = -1;

  TAILQ_INSERT_TAIL(&conf->list, ent, link);
  conf->ent[conf->num] = ent;
  conf->num++;
}

static void feed_arp_conf_line(struct conf_block *blk, char *line, int len)
{
  struct arp_conf * const conf = (struct arp_conf *)blk->conf;

  char address[WORD_LEN];
  int prefix;
  uint8_t haddr[ETH_ALEN] = {0};

  while (isspace(*line))
    line++, len--;

  if (sscanf(line, "%[0-9.]/%d %hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        address, &prefix, &haddr[0], &haddr[1], &haddr[2],
        &haddr[3], &haddr[4], &haddr[5]) != 8)
    return;

  struct _arp_entry *ent = (struct _arp_entry *)calloc(1, sizeof(struct _arp_entry));

  if (!ent)
  {
    MA_LOG("Could not allocate memory for arp_entry!");
    exit(EXIT_FAILURE);
  }

  MA_LOG1s("IP", address);
  MA_LOG2s("MAC", haddr, ETH_ALEN);
  ent->ip = inet_addr(address);
  ent->prefix = prefix;
  ent->mask = htonl((prefix == 0) ? 0 : ((-1) << (32 - prefix)));
  ent->masked_ip = ent->mask & ent->ip;
  memcpy(ent->haddr, haddr, ETH_ALEN);
  TAILQ_INSERT_TAIL(&conf->list, ent, link);
  conf->ent[conf->num] = ent;
  conf->num++;
}

static void feed_route_conf_line(struct conf_block *blk, char *line, int len)
{
	struct route_conf * const conf = (struct route_conf *)blk->conf;

	char address[WORD_LEN], dev_name[WORD_LEN];
	int prefix;

	/* skip first space */
	while (isspace(*line))
		line++, len--;

	if (sscanf(line, "%[0-9.]/%d %[^ ^\n^\t]", address, &prefix, dev_name) != 3)
		return;

	struct route_entry *ent = calloc(1, sizeof(struct route_entry));
	if (!ent) {
		MA_LOG("Could not allocate memory for route_entry!");
		exit(EXIT_FAILURE);
	}

  MA_LOG1s("IP", address);
  MA_LOG1s("dev name", dev_name);

	ent->ip = inet_addr(address);
	ent->mask = htonl((prefix == 0) ? 0 : ((-1) << (32 - prefix)));
	ent->masked_ip = ent->mask & ent->ip;
	ent->prefix = prefix;
	ent->nif = -1;
	strcpy(ent->dev_name, dev_name);

	TAILQ_INSERT_TAIL(&conf->list, ent, link);
	conf->ent[conf->num] = ent;
	conf->num++;
}

static void feed_nicfwd_conf_line(struct conf_block *blk, char *line, int len)
{
	struct nic_forward_conf * const conf = (struct nic_forward_conf *)blk->conf;
	char dev_name_in[WORD_LEN];
	char dev_name_out[WORD_LEN];

	/* skip first space */
	while (isspace(*line))
		line++, len--;

	if (sscanf(line, "%[^ ^\n^\t] %[^ ^\n^\t]", dev_name_in, dev_name_out) != 2)
		return;

	struct nic_forward_entry *ent = calloc(1, sizeof(struct nic_forward_entry));
	if (!ent) {
		MA_LOG("Could not allocate memory for nic forward entry!");
		exit(EXIT_FAILURE);
	}

	strcpy(ent->nif_in, dev_name_in);
	strcpy(ent->nif_out, dev_name_out);
	TAILQ_INSERT_TAIL(&conf->list, ent, link);
	conf->ent[conf->num] = ent;
	conf->num++;
}

static void mos_conf_addchild(struct conf_block *blk, struct conf_block *child)
{
	struct mos_conf * const conf = (struct mos_conf *)blk->conf;

	if (strcmp(child->name, NETDEV_BLOCK_NAME) == 0) {
		conf->netdev = child;
		conf->netdev_table = (struct netdev_conf *)child->conf;
	} else if (strcmp(child->name, ARP_BLOCK_NAME) == 0) {
		conf->arp = child;
		conf->arp_table = (struct arp_conf *)child->conf;
	} else if (strcmp(child->name, ROUTE_BLOCK_NAME) == 0) {
		conf->route = child;
		conf->route_table = (struct route_conf *)child->conf;
	} else if (strcmp(child->name, FORWARD_BLOCK_NAME) == 0) {
		conf->nic_forward = child;
		conf->nic_forward_table = (struct nic_forward_conf *)child->conf;
	} else
		return;
}

static int app_conf_isvalid(struct conf_block *blk)
{
	struct app_conf * const conf = (struct app_conf *)blk->conf;

	if (conf->app_argc <= 0)
		return 0;

	return 1;
}

static int mos_conf_isvalid(struct conf_block *blk)
{
	return 1;
}

static int netdev_conf_isvalid(struct conf_block *blk)
{
	return 1;
}

static int arp_conf_isvalid(struct conf_block *blk)
{
	return 1;
}

static int route_conf_isvalid(struct conf_block *blk)
{
	return 1;
}

static int nicfwd_conf_isvalid(struct conf_block *blk)
{
	return 1;
}

static void netdev_conf_print(struct conf_block *blk)
{
	struct netdev_conf * const conf = (struct netdev_conf *)blk->conf;

	printf(" +===== Netdev configuration (%d entries) =====\n",
			conf->num);

	struct netdev_entry *walk;
	TAILQ_FOREACH(walk, &conf->list, link) {
		printf(" | %s(idx: %d, HADDR: %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX) maps to CPU 0x%016lX\n",
				walk->dev_name, walk->ifindex,
				walk->haddr[0], walk->haddr[1], walk->haddr[2],
				walk->haddr[3], walk->haddr[4], walk->haddr[5],
				walk->cpu_mask);
	}
	printf(" |\n");
}

static void arp_conf_print(struct conf_block *blk)
{
	struct arp_conf * const conf = (struct arp_conf *)blk->conf;

	printf(" +===== Static ARP table configuration (%d entries) =====\n",
			conf->num);

	struct _arp_entry *walk;
	TAILQ_FOREACH(walk, &conf->list, link) {
		printf(" | IP: 0x%08X, NETMASK: 0x%08X, "
			   "HADDR: %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX\n",
			   ntohl(walk->ip), ntohl(walk->mask),
			   walk->haddr[0], walk->haddr[1], walk->haddr[2],
			   walk->haddr[3], walk->haddr[4], walk->haddr[5]);
	}
	printf(" |\n");
}

static void route_conf_print(struct conf_block *blk)
{
	struct route_conf * const conf = (struct route_conf *)blk->conf;

	printf(" +===== Routing table configuration (%d entries) =====\n",
			conf->num);

	struct route_entry *walk;
	TAILQ_FOREACH(walk, &conf->list, link) {
		printf(" | IP: 0x%08X, NETMASK: 0x%08X, INTERFACE: %s(idx: %d)\n",
			   ntohl(walk->ip), ntohl(walk->mask), walk->dev_name, walk->nif);
	}
	printf(" |\n");
}

static void nicfwd_conf_print(struct conf_block *blk)
{
	int i;
	struct nic_forward_conf * const conf = (struct nic_forward_conf *)blk->conf;

	printf(" +===== NIC Forwarding table configuration (%d entries) =====\n",
			conf->num);

	struct nic_forward_entry *walk;
	TAILQ_FOREACH(walk, &conf->list, link) {
		printf(" | NIC Forwarding Entry: %s <---> %s",
		       walk->nif_in, walk->nif_out);
	}
	printf(" |\n");

	printf(" | NIC Forwarding Index Table: |\n");
	
	for (i = 0; i < MAX_FORWARD_ENTRY; i++)
		printf( " | %d --> %d | \n", i, conf->nic_fwd_table[i]);
}

static void app_conf_print(struct conf_block *blk)
{
	struct app_conf * const conf = (struct app_conf *)blk->conf;

	printf("===== Application configuration =====\n");
	printf("| type:       %s\n", conf->type);
	printf("| run:        %s\n", conf->run);
	printf("| cpu_mask:   0x%016lX\n", conf->cpu_mask);
	printf("| ip_forward: %s\n", conf->ip_forward ? "forward" : "drop");
	printf("\n");
}

static void mos_conf_print(struct conf_block *blk)
{
	struct mos_conf * const conf = (struct mos_conf *)blk->conf;

	printf("===== MOS configuration =====\n");
	printf("| num_cores:       %d\n", conf->num_cores);
	printf("| nb_mem_channels: %d\n", conf->nb_mem_channels);
	printf("| max_concurrency: %d\n", conf->max_concurrency);
	printf("| clnt_rmem_size:       %d\n", conf->clnt_rmem_size);
	printf("| clnt_wmem_size:       %d\n", conf->clnt_wmem_size);
	printf("| serv_rmem_size:       %d\n", conf->serv_rmem_size);
	printf("| serv_wmem_size:       %d\n", conf->serv_wmem_size);
	printf("| tcp_tw_interval: %d\n", conf->tcp_tw_interval);
	printf("| tcp_timeout:     %d\n", conf->tcp_timeout);
	printf("| multiprocess:    %s\n", conf->multiprocess ? "true" : "false");
	printf("| mos_log:         %s\n", conf->mos_log);
	printf("| stat_print:      %s\n", conf->stat_print);
	printf("| forward:         %s\n", conf->forward ? "forward" : "drop");
	printf("|\n");
	if (conf->netdev)
		conf->netdev->print(conf->netdev);
	if (conf->arp)
		conf->arp->print(conf->arp);
	if (conf->route)
		conf->route->print(conf->route);
	if (conf->nic_forward)
		conf->nic_forward->print(conf->nic_forward);
	printf("\n");
}

static void init_app_block(struct config *config, struct conf_block *blk)
{
  assert(blk);

  blk->name = APP_BLOCK_NAME;
  blk->feed = feed_app_conf_line;
  blk->addchild = NULL;
  blk->isvalid = app_conf_isvalid;
  blk->print = app_conf_print;

  struct app_conf *conf = (struct app_conf *)calloc(1, sizeof(struct app_conf));
  
  if (!conf)
  {
    MA_LOG("Could not allocate memory for app_conf");
    exit(EXIT_FAILURE);
  }

  conf->cpu_mask = -1;
  conf->ip_forward = 1;
  conf->app_argc = 0;
  blk->conf = conf;
  blk->list = (typeof(blk->list))&config->app_blkh;
}

static void init_mos_block(struct config *config, struct conf_block *blk)
{
  assert(blk);

  blk->name = MOS_BLOCK_NAME;
  blk->feed = feed_mos_conf_line;
  blk->addchild = mos_conf_addchild;
  blk->isvalid = mos_conf_isvalid;
  blk->print = mos_conf_print;

  struct mos_conf *conf = (struct mos_conf *)calloc(1, sizeof(struct mos_conf));
  if (!conf)
  {
    MA_LOG("Could not allocate memory for mos_conf");
    exit(EXIT_FAILURE);
  }

  conf->forward = 1;
  conf->nb_mem_channels = 0;
  conf->max_concurrency = 100000;
  conf->no_ring_buffers = 0;

  conf->clnt_rmem_size = 8192;
  conf->clnt_wmem_size = 8192;
  conf->serv_rmem_size = 8192;
  conf->serv_wmem_size = 8192;

  conf->tcp_tw_interval = SEC_TO_USEC(TCP_TIMEWAIT) / TIME_TICK;
  conf->tcp_timeout = SEC_TO_USEC(TCP_TIMEOUT) / TIME_TICK;
  conf->cpu_mask = 0;
  blk->conf = conf;

  blk->list = (typeof(blk->list))&config->mos_blkh;
  config->mos = conf;
}

static void init_netdev_block(struct config *config, struct conf_block *blk)
{
  assert(blk);

  blk->name = NETDEV_BLOCK_NAME;
  blk->feed = feed_netdev_conf_line;
  blk->addchild = NULL;
  blk->isvalid = netdev_conf_isvalid;
  blk->print = netdev_conf_print;

  struct netdev_conf *conf = (struct netdev_conf *)calloc(1, sizeof(struct netdev_conf));
  if (!conf)
  {
    MA_LOG("Could not allocate memory for netdev_conf");
    exit(EXIT_FAILURE);
  }

  TAILQ_INIT(&conf->list);
  blk->conf = conf;

  blk->list = NULL;
}

static void init_arp_block(struct config *config, struct conf_block *blk)
{
  assert(blk);

  blk->name = ARP_BLOCK_NAME;
  blk->feed = feed_arp_conf_line;
  blk->addchild = NULL;
  blk->isvalid = arp_conf_isvalid;
  blk->print = arp_conf_print;

  struct arp_conf *conf = (struct arp_conf *)calloc(1, sizeof(struct arp_conf));
  if (!conf)
  {
    MA_LOG("Could not allocate memory for arp_conf");
    exit(EXIT_FAILURE);
  }

  TAILQ_INIT(&conf->list);
  blk->conf = conf;

  blk->list = NULL;
  config->mos->arp = blk;

  fetch_arp_kernel_entries(conf);
}

static void init_route_block(struct config *config, struct conf_block *blk)
{
  assert(blk);

  blk->name = ROUTE_BLOCK_NAME;
  blk->feed = feed_route_conf_line;
  blk->addchild = NULL;
  blk->isvalid = route_conf_isvalid;
  blk->print = route_conf_print;

  struct route_conf *conf = (struct route_conf *)calloc(1, sizeof(struct route_conf));
  if (!conf)
  {
    MA_LOG("Could not allocate memory for route_conf");
    exit(EXIT_FAILURE);
  }

  TAILQ_INIT(&conf->list);
  blk->conf = conf;

  blk->list = NULL;
  config->mos->arp = blk;

  fetch_route_kernel_entries(conf);
}

static void init_nic_forward_block(struct config *config, struct conf_block *blk)
{
  assert(blk);

  int i;

  blk->name = FORWARD_BLOCK_NAME;
  blk->feed = feed_nicfwd_conf_line;
  blk->addchild = NULL;
  blk->isvalid = nicfwd_conf_isvalid;
  blk->print = nicfwd_conf_print;

  struct nic_forward_conf *conf = (struct nic_forward_conf *)calloc(1, sizeof(struct nic_forward_conf));
  if (!conf)
  {
    MA_LOG("Could not allocate memory for route_conf");
    exit(EXIT_FAILURE);
  }

  for (i=0; i<MAX_FORWARD_ENTRY; i++)
    conf->nic_fwd_table[i] = -1;

  TAILQ_INIT(&conf->list);
  blk->conf = conf;

  blk->list = NULL;
  config->mos->nic_forward = blk;
}

static void init_config(struct config *config)
{
  int i;
  struct conf_block *blk;

  TAILQ_INIT(&g_free_blkh);
  TAILQ_INIT(&config->app_blkh);
  TAILQ_INIT(&config->mos_blkh);

  for (i=0; i<MAX_APP_BLOCK; i++)
  {
    blk = (struct conf_block *)calloc(1, sizeof(struct conf_block));
    if (!blk) goto init_config_err;
    init_app_block(config, blk);
    TAILQ_INSERT_TAIL(&g_free_blkh, blk, link);
    MA_LOG("Initialize app block");

    blk = (struct conf_block *)calloc(1, sizeof(struct conf_block));
    if (!blk) goto init_config_err;
    init_netdev_block(config, blk);
    TAILQ_INSERT_TAIL(&g_free_blkh, blk, link);
    MA_LOG("Initialize netdev block");
  }

  for (i=0; i<MAX_MOS_BLOCK; i++)
  {
    blk = (struct conf_block *)calloc(1, sizeof(struct conf_block));
    if (!blk) goto init_config_err;
    init_mos_block(config, blk);
    TAILQ_INSERT_TAIL(&g_free_blkh, blk, link);
    MA_LOG("Initialize mos block");

    blk = (struct conf_block *)calloc(1, sizeof(struct conf_block));
    if (!blk) goto init_config_err;
    init_arp_block(config, blk);
    TAILQ_INSERT_TAIL(&g_free_blkh, blk, link);
    MA_LOG("Initialize arp block");

    blk = (struct conf_block *)calloc(1, sizeof(struct conf_block));
    if (!blk) goto init_config_err;
    init_route_block(config, blk);
    TAILQ_INSERT_TAIL(&g_free_blkh, blk, link);
    MA_LOG("Initialize route block");

    blk = (struct conf_block *)calloc(1, sizeof(struct conf_block));
    if (!blk) goto init_config_err;
    init_nic_forward_block(config, blk);
    TAILQ_INSERT_TAIL(&g_free_blkh, blk, link);
    MA_LOG("Initialize nic forward block");
  }

  return;
init_config_err:
  MA_LOG("Can't allocate memory for blk_entry");
  exit(EXIT_FAILURE);
}

void print_conf(struct config *conf)
{
  struct conf_block *walk;
  TAILQ_FOREACH(walk, &conf->app_blkh, link)
  {
    if (walk->print)
      walk->print(walk);
  }

  TAILQ_FOREACH(walk, &conf->mos_blkh, link)
  {
    if (walk->print)
      walk->print(walk);
  }
}

static void check_conf_validity(struct config *conf)
{
  struct conf_block *walk;
  TAILQ_FOREACH(walk, &conf->app_blkh, link)
  {
    if (!walk->isvalid || !walk->isvalid(walk))
      goto __error;
  }

  TAILQ_FOREACH(walk, &conf->mos_blkh, link)
  {
    struct conf_block *child;

    if (!walk->isvalid || !walk->isvalid(walk))
      goto __error;

    child = ((struct mos_conf *)walk->conf)->netdev;
    if (!child->isvalid || !child->isvalid(child))
      goto __error;

    child = ((struct mos_conf *)walk->conf)->arp;
    if (!child->isvalid || !child->isvalid(child))
      goto __error;

    child = ((struct mos_conf *)walk->conf)->route;
    if (!child->isvalid || !child->isvalid(child))
      goto __error;
  }

  return;

__error:
  MA_LOG("Configuration validity failure!");
  if (walk && walk->print)
    walk->print(walk);
  exit(EXIT_FAILURE);
}

static struct conf_block *allocate_block(char *name, int len)
{
  struct conf_block *walk, *tmp;

  for (walk = TAILQ_FIRST(&g_free_blkh); walk != NULL; walk = tmp)
  {
    tmp = TAILQ_NEXT(walk, link);

    if (len == strlen(walk->name) && strncmp(walk->name, name, len) == 0)
    {
      TAILQ_REMOVE(&g_free_blkh, walk, link);
      if (walk->list)
        TAILQ_INSERT_TAIL(walk->list, walk, link);
      return walk;
    }
  }

  return NULL;
}

struct conf_block *detect_block(struct conf_block *blk, char *buf, int len)
{
  int depth = 0;
  char *blkname = NULL, *end = &buf[len];
  int blknamelen;
  struct conf_block *nblk;

  while (buf < end && isspace(*buf))
    buf++;

  if (detect_word(buf, len, &blkname, &blknamelen) < 0
      || blkname != buf)
    return NULL;

  buf += blknamelen;

  while (buf < end && isspace(*buf))
    buf++;

  if (buf >= end || *buf != '{')
    return NULL;

  buf++;

  while (buf < end && isspace(*buf))
    buf++;
  depth++;

  for (len = 0; &buf[len] < end; len++)
  {
    if (buf[len] == '{')
      depth++;
    else if (buf[len] == '}' && --depth == 0)
      break;
  }

  if (depth != 0)
    return NULL;

  if (!(nblk = allocate_block(blkname, blknamelen)))
    return NULL;

  if (blk)
  {
    assert(blk->addchild);
    blk->addchild(blk, nblk);
  }

  nblk->buf = buf;
  nblk->len = len;

  return nblk;
}

static void parse_block(struct conf_block *blk)
{
  char *line;
  int llen;

  LINE_FOREACH(line, llen, blk->buf, blk->len)
  {
    struct conf_block *nblk;

    if ((nblk = detect_block(blk, line, blk->len - (line - blk->buf))))
    {
      parse_block(nblk);
      line = &nblk->buf[nblk->len] + 1;
      llen = 0;
    }
    else
      blk->feed(blk, line, llen);
  }
}

void patch_config(struct config *config)
{
  int i;
  char *word, *str, *end;
  int wlen;

  g_config.mos->num_cores = num_cpus;
  word = NULL;

  i=0;
  struct conf_block *bwalk;
  TAILQ_FOREACH(bwalk, &g_config.app_blkh, link)
  {
    struct app_conf *app_conf = (struct app_conf *)bwalk->conf;
    g_config.mos->forward = g_config.mos->forward && app_conf->ip_forward;

    if (end_app_exists == 0 && !strcmp(app_conf->type, "end"))
      end_app_exists = 1;
    if (mon_app_exists == 0 && !strcmp(app_conf->type, "monitor"))
      mon_app_exists = 1;
    i++;
  }

  if (!end_app_exists && !mon_app_exists) mon_app_exists = 1;

  str = g_config.mos->stat_print;
  end = str + strlen(str);

  while(detect_word(str, end - str, &word, &wlen) == 0)
  {
    for (i=0; i<g_config.mos->netdev_table->num; i++)
    {
      if (strncmp(g_config.mos->netdev_table->ent[i]->dev_name, word, wlen) == 0)
      {
        g_config.mos->netdev_table->ent[i]->stat_print = TRUE;
      }
    }
    str = word + wlen;
  }
}

/**
 * @brief Configure the mssl
 * @param File name
 * @return Success/Failure
 */
int load_configuration_upper_half(const char *fname)
{
  char *line, *raw, *preprocessed;
  int llen;

  raw = read_conf(fname);
  preprocessed = preprocess_conf(raw);
  int len = strlen(preprocessed);

  init_config(&g_config);

  LINE_FOREACH(line, llen, preprocessed, len)
  {
    struct conf_block *nblk;

    if ((nblk = detect_block(NULL, line, len - (line - preprocessed))))
    {
      parse_block(nblk);
      line = &nblk->buf[nblk->len] + 1;
      llen = 0;
    }
  }

  check_conf_validity(&g_config);
  patch_config(&g_config);
  print_conf(&g_config);

  return 0;
}
