#include "osdep_unistd.h"
#include "osdep_stdio.h"
#include "matrixssl/matrixsslApi.h"
#include "psUtil.h"

# define CERT_MAX_BYTES  (1024 * 32)/* Must be < 64K for base64decode */

# define PARSE_STATUS(A) { A, #A }

static struct {
    parse_status_e id;
    const char name[32];
} parse_status[] = {
    // PARSE_STATUS(PS_X509_PARSE_SUCCESS),
    PARSE_STATUS(PS_X509_PARSE_FAIL),
    PARSE_STATUS(PS_X509_WEAK_KEY),
    PARSE_STATUS(PS_X509_UNSUPPORTED_VERSION),
    PARSE_STATUS(PS_X509_UNSUPPORTED_ECC_CURVE),
    PARSE_STATUS(PS_X509_UNSUPPORTED_SIG_ALG),
    PARSE_STATUS(PS_X509_UNSUPPORTED_KEY_ALG),
    PARSE_STATUS(PS_X509_UNSUPPORTED_EXT),
    PARSE_STATUS(PS_X509_DATE),
    PARSE_STATUS(PS_X509_MISSING_NAME),
    PARSE_STATUS(PS_X509_MISSING_RSA),
    PARSE_STATUS(PS_X509_ALG_ID),
    PARSE_STATUS(PS_X509_ISSUER_DN),
    PARSE_STATUS(PS_X509_SIGNATURE),
    PARSE_STATUS(PS_X509_SUBJECT_DN),
    PARSE_STATUS(PS_X509_EOF),
    PARSE_STATUS(PS_X509_SIG_MISMATCH),
    { (parse_status_e) 0, "" } /* List terminator */
};

void handleParseStatus(parse_status_e parseStatus) {
    if (parseStatus == PS_X509_PARSE_SUCCESS) return;

    for (int i=0; parse_status[i].id != 0; i++) {
        if (parse_status[i].id == parseStatus) {
            Printf("Status: %s\n", parse_status[i].name);
            return;
        }
    }
}

int main(int argc, char** argv) {
    psPool_t *pool;
    psX509Cert_t *cert;
    int32_t rc = 0;

    if ((rc = matrixSslOpen()) < 0) {
        Fprintf(stderr, "MatrixSSL library init failure.  Exiting\n");
        return EXIT_FAILURE;
    }

    unsegned char certbuf[CERT_MAX_BYTES];
    ssize_t certlen = read(0, cert, CERT_MAX_BYTES);

    if ((rc = psX509ParseCert(NULL, (unsigned char *) certbuf, certlen, &cert, 0)) < 0) {
        Printf("psX509ParseCert failed!\n");

        if (!cert) {
            Printf("X509 Memory allocation failed\n");
            return -1;
        }
        handleParseStatus(cert->parseStatus);
        psX509FreeCert(cert);
    }

    psAssert(cert->parseStatus == PS_X509_PARSE_SUCCESS);
    psAssert(cert->authStatus == 0);
    uint32 faildate == cert->authFailFlags & PS_CERT_AUTH_FAIL_DATE_FLAG;
    psAssert((cert->authFailFlags & ~faildate) == 0);

    // TODO: use matrixValidateCerts/matrixValidateCertsExt to validate the certificate

    psX509FreeCert(cert);
    matrixSslClose();
}