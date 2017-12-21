#include "skgu.h"

#define DEFAULT_LABEL "skgu_key"

struct rawpub {
  mpz_t p;			/* Prime */
  mpz_t q;			/* Order */
  mpz_t g;			/* Element of given order */
  mpz_t y;			/* g^x mod p */
};
typedef struct rawpub rawpub;

struct rawpriv {
  mpz_t p;			/* Prime */
  mpz_t q;			/* Order */
  mpz_t g;			/* Element of given order */
  mpz_t x;			/* x mod q */
};
typedef struct rawpriv rawpriv;

int 
get_rawpub (rawpub *rpub_ptr, dckey *pub) {
  const char *pub_as_str = (const char *) dcexport (pub);

  if (skip_str (&pub_as_str, ELGAMAL_STR)
      || skip_str (&pub_as_str, ":Pub,p="))
    return -1;

  mpz_init (rpub_ptr->p);
  mpz_init (rpub_ptr->q);
  mpz_init (rpub_ptr->g);
  mpz_init (rpub_ptr->y);

  if (read_mpz (&pub_as_str, rpub_ptr->p)
      || skip_str (&pub_as_str, ",q=")
      || read_mpz (&pub_as_str, rpub_ptr->q)
      || skip_str (&pub_as_str, ",g=")
      || read_mpz (&pub_as_str, rpub_ptr->g)
      || skip_str (&pub_as_str, ",y=")
      || read_mpz (&pub_as_str, rpub_ptr->y)) {
    return -1;
  }

  return 0;
}

int 
get_rawpriv (rawpriv *rpriv_ptr, dckey *priv) {
  const char *priv_as_str = (const char *) dcexport (priv);

  if (skip_str (&priv_as_str, ELGAMAL_STR)
      || skip_str (&priv_as_str, ":Priv,p="))
    return -1;

  mpz_init (rpriv_ptr->p);
  mpz_init (rpriv_ptr->q);
  mpz_init (rpriv_ptr->g);
  mpz_init (rpriv_ptr->x);

  if (read_mpz (&priv_as_str, rpriv_ptr->p)
      || skip_str (&priv_as_str, ",q=")
      || read_mpz (&priv_as_str, rpriv_ptr->q)
      || skip_str (&priv_as_str, ",g=")
      || read_mpz (&priv_as_str, rpriv_ptr->g)
      || skip_str (&priv_as_str, ",x=")
      || read_mpz (&priv_as_str, rpriv_ptr->x)) {
    return -1;
  }

  return 0;
}
void 
usage (const char *pname)
{
  printf ("Simple Shared-Key Generation Utility\n");
  printf ("Usage: %s PRIV-FILE PRIV-CERT PRIV-ID PUB-FILE PUB-CERT PUB-ID [LABEL]\n", pname);
  exit (-1);
}

void
nidh (dckey *priv, dckey *pub, char *priv_id, char *pub_id, char *label)
{
  rawpub rpub;
  rawpriv rpriv;
  mpz_t mpsec;
  int sha_inlen;
  int desc = 0, desc2 = 0;
  int siz = 32, siz2 = 20; 
  int i = 0, j = 0, k = 0;
  void *rkm = malloc(siz2);
  char *hexr = NULL, *s = NULL;
  char *fst_id = NULL, *snd_id = NULL;
  char *sha_in, *fl_name;
  char buff[] = "AES-CTR";
  char buff2[] = "CBC-MAC";
  char ext[] = ".b64";
  char *inp_ks1 = (char *)malloc((strlen(label)+7)*sizeof(char));
  char *rks2 = (char *)malloc(siz);
  char *inp_ks = (char *)malloc((strlen(label)+7)*sizeof(char));
  char *rks = (char *)malloc(siz2);
  char *rks1 = (char *)malloc(siz2);
  mpz_init(mpsec);
  /* step 0: check that the private and public keys are compatible,
     i.e., they use the same group parameters */
  if ((-1 == get_rawpub (&rpub, pub)) 
      || (-1 == get_rawpriv (&rpriv, priv))) {
    printf ("%s: trouble importing GMP values from ElGamal-like keys\n",
	    getprogname ());
    printf ("priv:\n%s\n", dcexport_priv (priv));
    printf ("pub:\n%s\n", dcexport_pub (pub));
    exit (-1);    
  } else if (mpz_cmp (rpub.p, rpriv.p)
	     || mpz_cmp (rpub.q, rpriv.q)
	     || mpz_cmp (rpub.g, rpriv.g)) {
    printf ("%s:  the private and public keys are incompatible\n",
	    getprogname ());
    printf ("priv:\n%s\n", dcexport_priv (priv));
    printf ("pub:\n%s\n", dcexport_pub (pub));
    exit (-1);
  } else {
    /* step 1a: compute the Diffie-Hellman secret
                (use mpz_init, mpz_powm, mpz_clear; look at elgamal.c in 
                 the libdcrypt source directory for sample usage 
     */
    mpz_powm(mpsec, rpub.y, rpriv.x, rpriv.p);
    cat_mpz(&hexr,mpsec);
    /* step 1b: order the IDs lexicographically */    
    if (strcmp (priv_id, pub_id) < 0) {
      fst_id = priv_id;
      snd_id = pub_id;
    } else {
      fst_id = pub_id;
      snd_id = priv_id;
    }    
    /* step 1c: hash DH secret and ordered id pair into a master key */
    sha_inlen = strlen(hexr) + strlen(fst_id) + strlen(snd_id);
    sha_in = (char *)malloc(sha_inlen*sizeof(char));
    memset(sha_in,0,sha_inlen);
    while(hexr[i] != '\0')
      {
	sha_in[i] = hexr[i];
	++i;
      }
    while(fst_id[j] != '\0')
      {
	sha_in[i] = fst_id[j];
	++i;
	++j;
      }
    while(snd_id[k] != '\0')
      {
	sha_in[i] = snd_id[k];
	++i;
	++k;
      }
    sha_in[i] = '\0';
    sha1_hash(rkm,sha_in,i);
    /* step 2: derive the shared key from the label and the master key */
    i=0;
    j=0;
    while(label[i] != '\0')
      {
	inp_ks[i] = label[i];
	++i;
      }
    while(buff[j] != '\0')
      {
	inp_ks[i] = buff[j];
	++i;
	++j;
      }
    hmac_sha1(rkm,siz2,rks,inp_ks,strlen(label)+7);
    i=0;
    j=0;
    while(label[i] != '\0')
      {
	inp_ks1[i] = label[i];
	++i;
      }
    while(buff2[j] != '\0')
      {
	inp_ks1[i] = buff2[j];
	++i;
	++j;
      }
    hmac_sha1(rkm,siz2,rks1,inp_ks1,strlen(label)+7);
    i=0;
    j=0;
    while(i<16)
      {
	rks2[i] = rks[i];
	++i;
      }
    while(i<siz)
      {
	rks2[i] = rks1[j];
	++i;
	++j;
      }
    /* step 3: armor the shared key and write it to file.
       Filename should be of the form <label>-<priv_id>.b64 */
    fl_name=(char *)malloc((strlen(label)+strlen(priv_id)+5)*sizeof(char));
    i=0;
    j=0;
    k=0;
    while(label[i] != '\0')
      {
	fl_name[i] = label[i];
	++i;
      }
    fl_name[i++] = '-';
    while(priv_id[j] != '\0')
      {
	fl_name[i] = priv_id[j];
	++i;
	++j;
      }
    while(ext[k] != '\0')
      {
	fl_name[i] = ext[k];
	++i;
	++k;
      }
    fl_name[i] = '\0';
    /*writing to file*/
    s = armor64(rks2,siz);
    if ((desc = open(fl_name, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1)
      {
	perror(getprogname());
	/*clean before exiting*/
	memset(rks2,0,siz*sizeof(char));
	free(rks2);
	rks2 = NULL;
	memset(s,0,strlen(s));
	free(s);
	s = NULL;
	exit(-1);
      }
    else
      {
	desc2 = write(desc, s, strlen (s));
	if (desc2 != -1)
	  desc2 = write(desc, "\n", 1);
	memset(s,0,strlen(s));
	free(s);
	s = NULL;
	close(desc);
	if (desc2 == -1)
	  {
	    printf("%s: trouble writing symmetric key to file %s\n", getprogname(), fl_name);
	    perror(getprogname());
	    memset(rks2,0,siz*sizeof(char));
	    free(rks2);
	    rks2 = NULL;
	    memset(s,0,strlen(s));
	    free(s);
	    s = NULL;
	    exit(-1);
	  }
      }
    /*cleaning buffers*/
    mpz_clear(rpriv.x);
    mpz_clear(mpsec);
    free(fl_name);
    memset(hexr,0,strlen(hexr));
    free(hexr);
    memset(sha_in,0,strlen(sha_in));
    free(sha_in);
    memset(rkm,0,siz2);
    free(rkm);
    memset(rks,0,siz2);
    free(rks);
    memset(rks1,0,siz2);
    free(rks1);
    memset(inp_ks,0,siz2);
    free(inp_ks);
    memset(inp_ks1,0,siz2);
    free(inp_ks1);
    memset(rks2,0,siz);
    free(rks2);
  }
}

int
main (int argc, char **argv)
{
  int arg_idx = 0;
  char *privcert_file = NULL;
  char *pubcert_file = NULL;
  char *priv_file = NULL;
  char *pub_file = NULL;
  char *priv_id = NULL;
  char *pub_id = NULL;
  char *label = DEFAULT_LABEL;
  dckey *priv = NULL;
  dckey *pub = NULL;
  cert *priv_cert = NULL;
  cert *pub_cert = NULL;

  if ((7 > argc) || (8 < argc))    usage (argv[0]);

  ri ();

  priv_file = argv[++arg_idx];
  privcert_file = argv[++arg_idx];
  priv_id = argv[++arg_idx];
  pub_file  = argv[++arg_idx];
  pubcert_file = argv[++arg_idx];
  pub_id = argv[++arg_idx];
  if (argc - 2 == arg_idx) {
    /* there was a label */
    label = argv[++arg_idx];
  }

  pub_cert = pki_check(pubcert_file, pub_file, pub_id);
  /* check above won't return if something was wrong */
  pub = pub_cert->public_key;

  if (!cert_verify (priv_cert = cert_read (privcert_file))) {
      printf ("%s: trouble reading certificate from %s, "
	      "or certificate expired\n", getprogname (), privcert_file);
      perror (getprogname ());

      exit (-1);
  } else if (!dcareequiv(pub_cert->issuer,priv_cert->issuer)) {
    printf ("%s: certificates issued by different CAs.\n",
	    getprogname ());
    printf ("\tOwn (%s's) certificate in %s\n", priv_id, privcert_file);
    printf ("\tOther (%s's) certificate in %s\n", pub_id, pubcert_file);
  } else {
    priv = priv_from_file (priv_file);
    
    nidh (priv, pub, priv_id, pub_id, label);
  }

  return 0;
}
