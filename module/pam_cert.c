/*
 *
 * Copyright (C) 2021 Markku Rossi.
 *
 * All rights reserved.
 *
 */

#include "pam_cert.h"

int
ask(pam_handle_t *pamh, const char *question, char **response_ret)
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
  char *answer = NULL;

  retval = pam_get_user(pamh, &username, NULL);
  if (retval != PAM_SUCCESS)
    return retval;

  retval = ask(pamh, "Certificate for 42: ", &answer);
  if (retval != PAM_SUCCESS)
    return retval;

  printf("Got: %s\n", answer);
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
