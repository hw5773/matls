/**
 * @file record_header.h
 * @author Hyunwoo Lee
 * @date 23 Mar 2018
 * @brief This file is to define a way to process a record layer header
 */

#ifndef __RECORD_HEADER_H__
#define __RECORD_HEADER_H__

#include <stdio.h>
#include <string.h>

#define NUM_OF_CONTENT_TYPES  5

extern const uint8_t content_type_num[NUM_OF_CONTENT_TYPES];
extern const char *content_type[NUM_OF_CONTENT_TYPES];

typedef struct recordhdr
{
  uint8_t content_type;
  uint8_t major;
  uint8_t minor;
  uint16_t length;
  uint8_t *fragment;
} RECORD_HDR;

int get_content_type_idx(int ct);
const char *get_content_type_string(int index);

#elif
#endif /* __RECORD_HEADER_H__ */
