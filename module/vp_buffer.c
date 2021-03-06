/*
 * Copyright (C) 2021 Markku Rossi.
 *
 * All rights reserved.
 */

#include "pam_cert.h"

void
vp_buffer_init(VPBuffer *buf)
{
  memset(buf, 0, sizeof(*buf));
}

void
vp_buffer_uninit(VPBuffer *buf)
{
  free(buf->data);
  vp_buffer_init(buf);
}

void
vp_buffer_reset(VPBuffer *buf)
{
  buf->offset = 0;
  buf->used = 0;
  buf->error = false;
}

bool
vp_buffer_error(VPBuffer *buf)
{
  return buf->error;
}

unsigned char *
vp_buffer_ptr(VPBuffer *buf)
{
  if (buf->error)
    return NULL;

  return buf->data + buf->offset;
}

size_t
vp_buffer_len(VPBuffer *buf)
{
  if (buf->error)
    return 0;

  return buf->used - buf->offset;
}


unsigned char *
vp_buffer_add_space(VPBuffer *buf, size_t len)
{
  unsigned char *ucp;

  if (buf->used + len > buf->allocated)
    {
      size_t size;
      unsigned char *n;

      for (size = buf->allocated + 1024; buf->used + len > size; size += 1024)
        ;

      n = realloc(buf->data, size);
      if (n == NULL)
        {
          buf->error = true;
          return NULL;
        }
      buf->data = n;
      buf->allocated = size;
    }

  ucp = buf->data + buf->used;
  buf->used += len;

  memset(ucp, 0, len);

  return ucp;
}

bool
vp_buffer_add_data(VPBuffer *buf, const unsigned char *data, size_t len)
{
  unsigned char *ucp;

  ucp = vp_buffer_add_space(buf, len);
  if (ucp == NULL)
    return false;

  memcpy(ucp, data, len);

  return true;
}

bool
vp_buffer_add_bool(VPBuffer *buf, uint8_t v)
{
  unsigned char *ucp;

  ucp = vp_buffer_add_space(buf, 1);
  if (ucp == NULL)
    return false;

  ucp[0] = v;

  return true;
}

bool
vp_buffer_add_uint32(VPBuffer *buf, uint32_t v)
{
  unsigned char *ucp;

  ucp = vp_buffer_add_space(buf, 4);
  if (ucp == NULL)
    return false;

  VP_PUT_UINT32(ucp, v);

  return true;
}

bool
vp_buffer_add_byte_arr(VPBuffer *buf, const void *data, size_t len)
{
  unsigned char *ucp;

  ucp = vp_buffer_add_space(buf, 4 + len);
  if (ucp == NULL)
    return false;

  VP_PUT_UINT32(ucp, len);
  memcpy(ucp + 4, data, len);

  return true;
}

unsigned char
vp_buffer_get_byte(VPBuffer *buf)
{
  unsigned char *ucp;

  if (buf->offset + 1 > buf->used)
    {
      buf->error = true;
      return 0;
    }
  ucp = buf->data + buf->offset;
  buf->offset++;

  return ucp[0];
}

uint32_t
vp_buffer_get_uint32(VPBuffer *buf)
{
  unsigned char *ucp;

  if (buf->offset + 4 > buf->used)
    {
      buf->error = true;
      return 0;
    }
  ucp = buf->data + buf->offset;
  buf->offset += 4;

  return VP_GET_UINT32(ucp);
}

unsigned char *
vp_buffer_get_byte_arr(VPBuffer *buf, size_t *len_ret)
{
  unsigned char *ucp;
  size_t len;

  *len_ret = 0;

  if (buf->offset + 4 > buf->used)
    {
      buf->error = true;
      return NULL;
    }
  ucp = buf->data + buf->offset;
  buf->offset += 4;

  len = VP_GET_UINT32(ucp);
  ucp += 4;

  if (buf->offset + len > buf->used)
    {
      buf->error = true;
      buf->offset = buf->used;
      return NULL;
    }

  buf->offset += len;

  *len_ret = len;

  return ucp;
}
