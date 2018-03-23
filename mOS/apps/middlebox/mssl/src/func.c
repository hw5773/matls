#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

uint8_t *strrep(uint8_t *str, uint8_t *substr, uint8_t *replacement)
{
  if (!str)
    goto out;

  if (!substr || !replacement)
    return str;

  uint8_t *tok = NULL;
  uint8_t *new = NULL;
  uint8_t *old = NULL;
  int old_len, sub_len, rep_len;

  new = strdup(str);
  sub_len = strlen(substr);
  rep_len = strlen(replacement);

  while ((tok = strstr(new, substr)))
  {
    old = new;
    old_len = strlen(old);

    new = (uint8_t *)malloc(old_len - sub_len + rep_len + 1);

    if (!new)
      goto err;

    memcpy(new, old, tok - old);
    memcpy(new + (tok - old), replacement, rep_len);
    memcpy(new + (tok - old) + rep_len, tok + sub_len, old_len - sub_len - (tok - old));
    memset(new + old_len - sub_len + rep_len, 0, 1);

    free(old);
  }

//  free(str);
  return new;

err:
  free(old);
out:
  return NULL;
}
