#include "pv.h"

void
encrypt_file (const char *ctxt_fname, void *raw_sk, size_t raw_len, int fin)
{
  /*declaring variables*/
  int ctxtfd;
  int numread;
  int n;
  int i;
  int BLKSIZE = 16;
  long int finsize;
  char *outputbuf;
  char *outputbak;
  char *ptxtbuf;
  char *ctxtbuf;
  char *macbuf;
  char *ctrkey;
  char *mackey;
  char *nonce;
  aes_ctx aesctr;
  aes_ctx aescbcmac;  
  /* Create the ciphertext file---the content will be encrypted, 
   * so it can be world-readable! */
  if ( (ctxtfd = open(ctxt_fname,O_WRONLY|O_TRUNC|O_CREAT,0644)) == -1 ) 
    {
      perror(getprogname());
      memset(raw_sk,0,raw_len*sizeof(char));
      free(raw_sk);
      raw_sk = NULL;
      exit(-1);
    }
  /* initialize the pseudorandom generator (for the IV) */
  ri();
  /* The buffer for the symmetric key actually holds two keys: */
  /* use the first key for the AES-CTR encryption ...*/
  memcpy(ctrkey,raw_sk,CCA_STRENGTH*sizeof(char));
  aes_setkey(&aesctr,ctrkey,CCA_STRENGTH);
  /* ... and the second part for the AES-CBC-MAC */
  memcpy(mackey,raw_sk+CCA_STRENGTH,CCA_STRENGTH*sizeof(char));
  aes_setkey(&aescbcmac,mackey,CCA_STRENGTH);
  /* Now start processing the actual file content using symmetric encryption */
  /* Remember that CTR-mode needs a random IV (Initialization Vector) */
  prng_getbytes(nonce,BLKSIZE);
  numread = read(fin,ptxtbuf,BLKSIZE);
  write_chunk(ctxtfd,nonce,BLKSIZE);
  while (numread > 0)
    {
      aes_encrypt(&aesctr,ctxtbuf,nonce);
      /* xor ptxtbuf and AES(nonce) */
      for (i=0; i<numread; ++i)
	ctxtbuf[i] = ctxtbuf[i] ^ ptxtbuf[i];
      /* add 1 to nonce */
      incrstr(nonce,BLKSIZE);
      /* save ctxtbuf chunk to outputbuf */
      memcpy(outputbuf,ctxtbuf,numread*sizeof(char));
      /* Compute the AES-CBC-MAC while you go */
      /******************TODO******************/
      /* use existing buffer for cbc-mac calc */
      /* macbuf at first iteration is IV (finsize) */
      for (i=0; i<BLKSIZE; ++i)
	{
	  /* normal case, we read a full BLKSIZE block */
	  if (i<numread)
	    ctxtbuf[i] = ctxtbuf[i] ^ macbuf[i];
	  /* special case, we read less than full BLKSIZE block 
	   * set extra bits in buffer to 0 */
	  else if (i>=numread)
	    ctxtbuf[i] = 0;
	}
      aes_encrypt(&aescbcmac,macbuf,ctxtbuf);
      /* increment outputbuf */
      outputbuf += numread;
      /* read next ptxt block from file*/
      numread = read(fin,ptxtbuf,BLKSIZE);
    }
  if ( (n = write(ctxtfd,outputbak,finsize)) < 0 )
    printf("failed to write ctxt file\n");
  /* write aes-cbc-mac */
  else
    write_chunk(ctxtfd,macbuf,BLKSIZE);

  /* clean up! */
  memset(outputbak,0,finsize*sizeof(char));
  memset(ptxtbuf,0,BLKSIZE*sizeof(char));
  memset(ctxtbuf,0,BLKSIZE*sizeof(char));
  memset(macbuf,0,BLKSIZE*sizeof(char));
  memset(ctrkey,0,CCA_STRENGTH*sizeof(char));
  memset(mackey,0,CCA_STRENGTH*sizeof(char));
  memset(nonce,0,BLKSIZE*sizeof(char));
  aes_clrkey(&aesctr);
  aes_clrkey(&aescbcmac);
  free(ptxtbuf);
  free(ctxtbuf);
  free(ctrkey);
  free(macbuf);
  free(mackey);
  free(nonce);
  free(outputbak);
  ptxtbuf   = NULL;
  ctxtbuf   = NULL;
  ctrkey    = NULL;
  macbuf    = NULL;
  mackey    = NULL;
  nonce     = NULL;
  outputbak = NULL;
  outputbuf = NULL;
  close(ctxtfd);

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
    memset(raw_sk,0,raw_len);
    free(raw_sk);
    raw_sk = NULL;
    close (fdptxt);
  }

  return 0;
}
