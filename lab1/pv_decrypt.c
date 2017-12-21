#include "pv.h"

void
encrypt_file (const char *ctxt_fname, void *raw_sk, size_t raw_len, int fin)
{
  /*declaring variables*/
  aes_ctx aescbcmac;
  aes_ctx aesctr;
  
  /* Create the ciphertext file---the content will be encrypted, 
   * so it can be world-readable! */
  
  /* initialize the pseudorandom generator (for the IV) */
  ri();
  /* The buffer for the symmetric key actually holds two keys: */
  /* use the first key for the AES-CTR encryption ...*/
  memcpy(ctrkey,raw_sk,CCA_STRENGTH*sizeof(char));
  aes_setkey(&aesctr,ctrkey,CCA_STRENGTH);
  /* ... and the second part for the AES-CBC-MAC */
  memcpy(mackey,raw_sk+CCA_STRENGTH,CCA_STRENGTH*sizeof(char));
  aes_setkey(&aescbcmac,mackey,CCA_STRENGTH);
}

void 
usage (const char *pname)
{
  printf ("Personal Vault: Encryption \n");
  printf ("Usage: %s SK-FILE PTEXT-FILE CTEXT-FILE\n", pname);
  printf ("       Exits if either SK-FILE or PTEXT-FILE don't exist.\n");
  printf ("       Otherwise, encrpyts the content of PTEXT-FILE under\n");
  printf ("       sk, and place the resulting ciphertext in CTEXT-FILE.\n");
  printf ("       If CTEXT-FILE existed, any previous content is lost.\n");

  exit (1);
}

int 
main (int argc, char **argv)
{
  int fdsk, fdptxt;
  char *raw_sk;
  size_t raw_len;
  if (argc != 4) {
    usage (argv[0]);
  }   /* Check if argv[1] and argv[2] are existing files */
  else if (((fdsk = open (argv[1], O_RDONLY)) == -1)
	   || ((fdptxt = open (argv[2], O_RDONLY)) == -1)) {
    if (errno == ENOENT) {
      usage (argv[0]);
    }
    else {
      perror (argv[0]);
      exit (-1);
    }
  }
  else {
    setprogname (argv[0]);
    /* Import symmetric key from argv[1] */
    if (!(import_sk_from_file (&raw_sk, &raw_len, fdsk))) {
      printf ("%s: no symmetric key found in %s\n", argv[0], argv[1]);      
      close (fdsk);
      exit (2);
    }
    close (fdsk);
    /* Enough setting up---let's get to the crypto... */
    encrypt_file (argv[3], raw_sk, raw_len, fdptxt);    
    /* scrub the buffer that's holding the key before exiting */
    memset(raw_sk,0,raw__len);
    free(raw_sk);
    raw_sk = NULL;
    close (fdptxt);
  }

  return 0;
}
