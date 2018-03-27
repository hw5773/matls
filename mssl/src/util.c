#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include "include/logs.h"
#include "include/util.h"

int mystrtol(const char *nptr, int base)
{
  int rval;
  char *endptr;

  errno = 0;
  rval = strtol(nptr, &endptr, 10);

  if ((errno == ERANGE && (rval == LONG_MAX || rval == LONG_MIN))
      || (errno != 0 && rval == 0))
  {
    MA_LOG("Error: strtol");
    exit(EXIT_FAILURE);
  }

  if (endptr == nptr)
  {
    MA_LOG("Parsing strtol error!");
    exit(EXIT_FAILURE);
  }

  return rval;
}

int str_to_args(char *str, int *argc, char **argv, int max_argc)
{

	uint8_t single_quotes;
	uint8_t double_quotes;
	uint8_t delim;

	single_quotes = 0;
	double_quotes = 0;
	delim = 1;

	*argc = 0;

	int i;
	int len = strlen(str);
	for (i = 0; i < len; i++) {

		if (str[i] == '\'') {
			if (single_quotes)
				str[i] = '\0';
			else
				i++;
			single_quotes = !single_quotes;
			goto __non_space;
		} else if (str[i] == '\"') {
			if (double_quotes)
				str[i] = '\0';
			else
				i++;
			double_quotes = !double_quotes;
			goto __non_space;
		}

		if (single_quotes || double_quotes)
			continue;

		if (isspace(str[i])) {
			delim = 1;
			str[i] = '\0';
			continue;
		}
__non_space:
		if (delim == 1) {
			delim = 0;
			argv[(*argc)++] = &str[i];
			if (*argc > max_argc)
				break;
		}
	}

	argv[*argc] = NULL;

	return 0;
}

