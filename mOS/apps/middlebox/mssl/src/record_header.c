/**
 * @file record_header.c
 * @author Hyunwoo Lee
 * @date 23 Mar 2018
 * @brief This file is to implement the functions of the record layer header
 */

#include <stdint.h>
#include "../include/record_header.h"

const uint8_t content_type_num[] = { 20, 21, 22, 23, 41 };
const char *content_type[] =
{
  "change cipher spec",
  "alert",
  "handshake",
  "application data",
  "matls application data"
};

/**
 * @brief Get the index of the content type in the string array
 * @param ct Received content type number
 * @return Index of the content type string
 */
int get_content_type_idx(int ct)
{
  int i = -1;

  for (i=0; i<(sizeof(content_type_num)/sizeof(int)); i++)
  {
    if (content_type_num[i] == ct)
      break;
  }

  return i;
}

/**
 * @brief Get the string of the content type
 * @param index Index of the content type string (get from
 * get_content_type_idx)
 * @return Name of the content type string
 */
const char *get_content_type_string(int index)
{
  return content_type[index];
}
