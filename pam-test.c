/*
 * pam-test.c
 */

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

const struct pam_conv conv =
  {
    misc_conv,
    NULL,
  };

int
main(int argc, char *argv[])
{
  pam_handle_t *pamh = NULL;
  int retval;
  const char *user;

  if (argc != 2)
    {
      printf("Usage: app [username]\n");
      exit(1);
    }

  user = argv[1];

  retval = pam_start("check_user", user, &conv, &pamh);
  if (retval != PAM_SUCCESS)
    {
      printf("pam_start: %s\n", pam_strerror(pamh, retval));
      exit(1);
    }

  retval = pam_authenticate(pamh, 0);
  if (retval != PAM_SUCCESS)
    {
      printf("pam_authenticate: %s\n", pam_strerror(pamh, retval));
      exit(1);
    }

  retval = pam_acct_mgmt(pamh, 0);
  if (retval != PAM_SUCCESS)
    {
      printf("pam_acct_mgmt: %s\n", pam_strerror(pamh, retval));
      exit(1);
    }

  retval = pam_end(pamh, retval);
  if (retval != PAM_SUCCESS)
    {
      printf("pam_end: %s\n", pam_strerror(pamh, retval));
      exit(1);
    }

  return 0;
}
