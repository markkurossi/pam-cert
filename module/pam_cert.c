/*
 *
 * Copyright (C) 2021 Markku Rossi.
 *
 * All rights reserved.
 *
 */

#include "pam_cert.h"

char *
make_challenge()
{
  VPBuffer buf;
  char hostname[256];
  int ret;
  unsigned char *ucp;
  size_t len;
  unsigned char *challenge;
  size_t challenge_len;

  vp_buffer_init(&buf);

  ret = gethostname(hostname, sizeof(hostname));
  if (ret != 0)
    return NULL;

  vp_buffer_add_data(&buf, (unsigned char *) hostname, strlen(hostname));
  vp_buffer_add_uint32(&buf, time(NULL));

  ucp = vp_buffer_ptr(&buf);
  if (ucp == NULL)
    {
      vp_buffer_uninit(&buf);
      return NULL;
    }
  len = vp_buffer_len(&buf);

  challenge = base64_encode(ucp, len, &challenge_len);

  vp_buffer_uninit(&buf);

  return (char *) challenge;
}

int
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

int
pam_sm_authenticate(pam_handle_t *pamh, int flags,int argc, const char **argv)
{
  int retval;
  const char *username;
  char *challenge;
  char *answer = NULL;
  char buf[4096];

  retval = pam_get_user(pamh, &username, NULL);
  if (retval != PAM_SUCCESS)
    return retval;

  challenge = make_challenge();
  if (challenge == NULL)
    return PAM_AUTH_ERR;

  snprintf(buf, sizeof(buf), "Challenge  : %sCertificate: ", challenge);

  retval = ask(pamh, buf, &answer);
  if (retval != PAM_SUCCESS)
    return retval;

  if (strcmp(answer, "no") == 0)
    {
      printf("Invalid certificate\n");
      free(answer);
      return PAM_AUTH_ERR;
    }

  printf("Valid certificate for user %s\n", username);

  free(answer);

  return PAM_SUCCESS;
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
