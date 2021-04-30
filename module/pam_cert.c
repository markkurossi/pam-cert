/*
 *
 * Copyright (C) 2021 Markku Rossi.
 *
 * All rights reserved.
 *
 */

#include "pam_cert.h"

static char *
format_time(time_t time, char *buf, size_t buflen)
{
  struct tm tm;

  strftime(buf, buflen, "%FT%T%z", gmtime_r(&time, &tm));

  return buf;
}

static char *
make_challenge(const char *username)
{
  VPBuffer buf;
  char hostname[256];
  int ret;
  unsigned char *ucp;
  size_t len;
  unsigned char *challenge;
  size_t challenge_len;
  time_t now = time(NULL);
  char timestamp[256];

  vp_buffer_init(&buf);

  ret = gethostname(hostname, sizeof(hostname));
  if (ret != 0)
    return NULL;

  vp_buffer_add_byte_arr(&buf, username, strlen(username));
  vp_buffer_add_byte_arr(&buf, hostname, strlen(hostname));
  vp_buffer_add_uint32(&buf, now);

  ucp = vp_buffer_ptr(&buf);
  if (ucp == NULL)
    {
      vp_buffer_uninit(&buf);
      return NULL;
    }
  len = vp_buffer_len(&buf);

  challenge = base64_encode(ucp, len, &challenge_len);

  vp_buffer_uninit(&buf);

 printf("Username   : %s\nHostname   : %s\nTime       : %s\n",
        username, hostname, format_time(now, timestamp, sizeof(timestamp)));

  return (char *) challenge;
}

static int
ask(pam_handle_t *pamh, char *question, char **response_ret)
{
  struct pam_conv *conv;
  struct pam_message msg;
  const struct pam_message *msgp;
  int retry;
  int pam_err;

  pam_err = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
  if (pam_err != PAM_SUCCESS)
    return pam_err;

  msg.msg_style = PAM_PROMPT_ECHO_ON;
  msg.msg = question;
  msgp = &msg;

  for (retry = 0; retry < 3; retry++)
    {
      struct pam_response *resp = NULL;

      pam_err = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);
      if (resp != NULL)
        {
          if (pam_err == PAM_SUCCESS)
            {
              *response_ret = resp->resp;
              free(resp);
              return PAM_SUCCESS;
            }

          free(resp->resp);
          free(resp);
        }
    }

  return PAM_AUTH_ERR;
}

static bool
match_username(unsigned char *ucp, size_t len, const char *username)
{
  if (strlen(username) != len)
    return false;

  return memcmp(ucp, username, len) == 0;
}

static bool
match_hostname(unsigned char *ucp, size_t len)
{
  char hostname[256];

  if (gethostname(hostname, sizeof(hostname)) != 0)
    return false;

  if (strlen(hostname) != len)
    {
      printf("hostname length: %ld != %ld\n", strlen(hostname), len);
      return false;
    }
  if (memcmp(hostname, ucp, len) != 0)
    {
      printf("hostname: %s != %.*s\n", hostname, (int) len, ucp);
      return false;
    }
  return true;
}

static int
time_delta(uint32_t from, uint32_t to)
{
  if (from > to)
    return (int) (from - to);

  return (int) (to - from);
}

static bool
match_time(uint32_t sign_time, uint32_t host_time)
{
  uint32_t now = (uint32_t) time(NULL);
  int allowed = 60 * 60 * 2;

  if (time_delta(host_time, now) > allowed)
    {
      printf("delta(host,now) too large\n");
      return false;
    }
  return true;
}

static bool
verify_token(unsigned char *token, size_t token_len, const char *pam_username)
{
  VPBuffer buf;
  unsigned char *fromuser;
  size_t fromuser_len;
  unsigned char *username;
  size_t username_len;
  unsigned char *hostname;
  size_t hostname_len;
  uint32_t sign_time, host_time;
  char timestamp[256];

  vp_buffer_init(&buf);

  if (!vp_buffer_add_data(&buf, token, token_len))
    goto error;

  fromuser = vp_buffer_get_byte_arr(&buf, &fromuser_len);
  username = vp_buffer_get_byte_arr(&buf, &username_len);
  hostname = vp_buffer_get_byte_arr(&buf, &hostname_len);
  sign_time = vp_buffer_get_uint32(&buf);
  host_time = vp_buffer_get_uint32(&buf);

  if (vp_buffer_error(&buf))
    goto error;

  printf("token      : %s %.*s => %.*s@%.*s\n",
         format_time((time_t) host_time, timestamp, sizeof(timestamp)),
         (int) fromuser_len, fromuser,
         (int) username_len, username,
         (int) hostname_len, hostname);

  if (!match_username(username, username_len, pam_username))
    {
      printf("username mismach\n");
      goto error;
    }
  if (!match_hostname(hostname, hostname_len))
    {
      printf("hostname mismach\n");
      goto error;
    }
  if (!match_time(sign_time, host_time))
    {
      printf("timestamp mismatch\n");
      goto error;
    }

  vp_buffer_uninit(&buf);
  return true;


  /* Error handling */
 error:
  vp_buffer_uninit(&buf);
  return false;
}

static bool
verify_cert(unsigned char *cert, size_t cert_len, unsigned char *pub,
            const char *username)
{
  VPBuffer buf;
  unsigned char *token;
  size_t token_len;
  unsigned char *signature;
  size_t signature_len;

  vp_buffer_init(&buf);

  if (!vp_buffer_add_data(&buf, cert, cert_len))
    {
      vp_buffer_uninit(&buf);
      return false;
    }

  token = vp_buffer_get_byte_arr(&buf, &token_len);
  signature = vp_buffer_get_byte_arr(&buf, &signature_len);

  if (vp_buffer_error(&buf))
    {
      vp_buffer_uninit(&buf);
      return false;
    }

  if (signature_len != 64)
    {
      printf("invalid signature length: %ld", signature_len);
      vp_buffer_uninit(&buf);
      return false;
    }

  if (!ed25519_verify(signature, token, token_len, pub))
    {
      printf("signature verification failed\n");
      vp_buffer_uninit(&buf);
      return false;
    }

  if (!verify_token(token, token_len, username))
    {
      vp_buffer_uninit(&buf);
      return false;
    }

  vp_buffer_uninit(&buf);

  return true;
}

static unsigned char *
load_public_key()
{
  FILE *fp;
  unsigned char buf[4096];
  size_t got;
  unsigned char *pub;
  size_t pub_len;

  fp = fopen("/etc/ca.pub", "r");
  if (fp == NULL)
    return NULL;

  got = fread(buf, 1, sizeof(buf), fp);
  fclose(fp);

  pub = base64_decode(buf, got, &pub_len);
  if (pub == NULL)
    {
      printf("failed to decode public key\n");
      return NULL;
    }
  if (pub_len != 32)
    {
      printf("invalid public key length: got %ld, expected 32", pub_len);
      free(pub);
      return NULL;
    }

  return pub;
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags,int argc, const char **argv)
{
  int retval;
  const char *username;
  char *challenge = NULL;
  char *answer = NULL;
  char buf[4096];
  unsigned char *cert = NULL;
  size_t cert_len;
  unsigned char *pub = NULL;

  retval = pam_get_user(pamh, &username, NULL);
  if (retval != PAM_SUCCESS)
    return retval;

  challenge = make_challenge(username);
  if (challenge == NULL)
    goto error;

  snprintf(buf, sizeof(buf), "Challenge  : %sCertificate: ", challenge);

  retval = ask(pamh, buf, &answer);
  if (retval != PAM_SUCCESS)
    {
      printf("ask failed\n");
      goto error;
    }

  cert = base64_decode((unsigned char *) answer, strlen(answer), &cert_len);
  if (cert == NULL)
    {
      printf("base64_decode failed\n");
      goto error;
    }

  pub = load_public_key();
  if (pub == NULL)
    {
      printf("failed to load public key\n");
      goto error;
    }

  if (!verify_cert(cert, cert_len, pub, username))
    goto error;

  printf("Valid certificate for user %s\n", username);

  free(challenge);
  free(answer);
  free(cert);
  free(pub);

  return PAM_SUCCESS;


  /* Error handling */

 error:

  free(challenge);
  free(answer);
  free(cert);
  free(pub);

  return PAM_AUTH_ERR;
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}
