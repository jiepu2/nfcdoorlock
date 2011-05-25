#include <string.h>

#include <nfc/nfc.h>
#include <nfc/nfc-messages.h>

//#include <openssl/dsa.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define MAX_FRAME_LEN 264

static byte_t abtRx[MAX_FRAME_LEN];
static size_t szRx;
static nfc_device_t *pnd;

void print_hex(const byte_t * pbtData, const size_t szBytes) {
	size_t szPos;

	for (szPos = 0; szPos < szBytes; szPos++) {
		printf("%02x  ", pbtData[szPos]);
	}
	printf("\n");
}

int main(int argc, char *argv[]) {
	while (true) {

		printf("Waiting for tag/reader\n");
		pnd = nfc_connect(NULL);
		while (pnd == NULL) {
			system("sleep 1");
			printf("Waiting for tag/reader\n");
			pnd = nfc_connect(NULL);
		}

		nfc_target_t nt = {
				.nm.nmt = NMT_ISO14443A,
				.nm.nbr = NBR_UNDEFINED,
				.nti.nai.abtAtqa = { 0x00, 0x04 },
				.nti.nai.abtUid = { 0x08, 0x00, 0xb0, 0x0b },
				.nti.nai.btSak = 0x20,
				.nti.nai.szUidLen = 4,
				.nti.nai.szAtsLen = 0, };

		printf("Init reader as listener\n");
		if (!nfc_target_init(pnd, &nt, abtRx, &szRx)) {
			nfc_perror(pnd, "nfc_target_init");
			nfc_disconnect(pnd);
			continue;
		}

		printf("Receiving\n");
		nfc_target_receive_bytes(pnd, abtRx, &szRx);
		nfc_target_send_bytes(pnd, (const byte_t*) "\x6a\x87", 2);
		nfc_target_receive_bytes(pnd, abtRx, &szRx);
		print_hex(abtRx, szRx);
		nfc_target_send_bytes(pnd, (const byte_t*) "\x6a\x87", 2);
		nfc_target_receive_bytes(pnd, abtRx, &szRx);
		print_hex(abtRx, szRx);

		if (abtRx[0] != (byte_t) 0xAE) {// Check for Af (are you a door)?
			nfc_disconnect(pnd);
			continue;
		}

		printf("Allocate challenge\n");
		unsigned char* challenge = malloc(16);
		if (!RAND_bytes(challenge, 16)) {
			if (!RAND_pseudo_bytes(challenge, 16)) {
				free(challenge);
				nfc_disconnect(pnd);
				continue;
			}
		}

		printf("Send challenge\n");
		byte_t send[18];
		send[0] = (char) 0x90;
		send[1] = (char) 0x00;
		memcpy(&send + 2, challenge, 16);
		nfc_target_send_bytes(pnd, (const byte_t*) &send, 18); // // Yes door! Send challenge and doorid

		printf("Receive cert info\n");

		nfc_target_receive_bytes(pnd, abtRx, &szRx);
		nfc_target_send_bytes(pnd, (const byte_t*) "\x90\x00", 2);
		print_hex(abtRx, szRx);

		if (abtRx[0] == (byte_t) 0xAE) {
			int noblocks = abtRx[1];
			int blocksize = abtRx[2];
			int overflow = abtRx[3];
			int certsize = noblocks * blocksize + overflow;
			unsigned char* certin = malloc(certsize);
			unsigned char* signature;
			unsigned int siglength;
			printf("	Size: %d, NoBlocks: %d, Blocksize: %d, Overflow: %d\n",
					certsize, noblocks, blocksize, overflow);

			if (overflow > 0) {
				noblocks++;
			}

			int i;
			for (i = 0; i < noblocks +1; i++) {
				nfc_target_receive_bytes(pnd, abtRx, &szRx);
				print_hex(abtRx, szRx);
				nfc_target_send_bytes(pnd, (const byte_t*) "\x90\x00", 2); // receive cert
				if (i< noblocks)
				{
					memcpy(certin + (i * blocksize), abtRx, szRx);
				} else {
					signature = malloc(szRx);
					siglength = szRx;
					memcpy(signature, abtRx, szRx);
				}
			}

			X509_STORE* store;
			X509* phone = NULL;
			X509_STORE_CTX *ctx;

			phone = d2i_X509(NULL, (const unsigned char **)&certin, certsize);
			certin = certin - certsize;
			free(certin);
			certin = NULL;
			ctx = X509_STORE_CTX_new();
			store = X509_STORE_new();
			X509_STORE_load_locations(store, "certs/ca.pem", NULL);
			X509_STORE_set_default_paths(store);

			X509_STORE_CTX_init(ctx, store, phone, NULL);

			printf("Verifying Certificate\n");
			if (X509_verify_cert(ctx) == 0) {
				printf("Certificate Valid\n");

				printf("Verifying Signature\n");

				EVP_PKEY* key = X509_get_pubkey(phone);

				EVP_MD_CTX ct;
				const EVP_MD *type;

				EVP_MD_CTX_init(&ct);
				type = EVP_sha1();

				EVP_VerifyInit_ex(&ct,type, NULL);
				EVP_VerifyUpdate(&ct,challenge,16);

				if (EVP_VerifyFinal(&ct, signature, siglength, key) == 0) {
					printf("Signature Valid\n");
					system("./door.sh");
				} else {
					printf("Signature INValid\n");
				}

				EVP_MD_CTX_cleanup(&ct);
				EVP_cleanup();
			} else {
				printf("Certificate INValid\n");
			}

			free(signature);
			X509_STORE_CTX_free(ctx);
			X509_STORE_free(store);
			X509_free(phone);
		} else {
			printf("Invalid Cert Info\n");
		}

		free(challenge);
		nfc_disconnect(pnd);
		system("sleep 3");
	}
	exit(EXIT_SUCCESS);
}

