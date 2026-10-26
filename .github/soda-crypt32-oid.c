#define CRYPT_OID_INFO_HAS_EXTRA_FIELDS
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static unsigned int checks, failed;

static void check_info(const char *kind, PCCRYPT_OID_INFO info, const char *oid, const WCHAR *cng)
{
    ++checks;
    printf("query=%s oid=%s found=%u", kind, oid, (unsigned int)!!info);
    if (info)
    {
        printf(" size=%lu algid=%#x cng=%ls extra=%ls", info->cbSize, info->Algid,
                info->pwszCNGAlgid ? info->pwszCNGAlgid : L"<null>",
                info->pwszCNGExtraAlgid ? info->pwszCNGExtraAlgid : L"<null>");
    }
    if (!info || info->cbSize != sizeof(*info) || strcmp(info->pszOID, oid) ||
            !info->pwszCNGAlgid || wcscmp(info->pwszCNGAlgid, cng) ||
            !info->pwszCNGExtraAlgid || *info->pwszCNGExtraAlgid)
        ++failed;
    putchar('\n');
}

int main(void)
{
    static const struct
    {
        const char *oid;
        const WCHAR *name;
        const WCHAR *cng;
    } tests[] =
    {
        {szOID_RSA_MD2, L"md2", L"MD2"},
        {szOID_RSA_MD4, L"md4", L"MD4"},
        {szOID_RSA_MD5, L"md5", L"MD5"},
        {szOID_OIWSEC_sha1, L"sha1", L"SHA1"},
        {szOID_NIST_sha256, L"sha256", L"SHA256"},
        {szOID_NIST_sha384, L"sha384", L"SHA384"},
        {szOID_NIST_sha512, L"sha512", L"SHA512"}
    };
    unsigned int i;

    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
    {
        check_info("hash", CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY,
                (void *)tests[i].oid, CRYPT_HASH_ALG_OID_GROUP_ID), tests[i].oid, tests[i].cng);
        check_info("all", CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY,
                (void *)tests[i].oid, 0), tests[i].oid, tests[i].cng);
        check_info("name", CryptFindOIDInfo(CRYPT_OID_INFO_NAME_KEY,
                (void *)tests[i].name, CRYPT_HASH_ALG_OID_GROUP_ID), tests[i].oid, tests[i].cng);
        ++checks;
        if (CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, (void *)tests[i].oid, CRYPT_ENCRYPT_ALG_OID_GROUP_ID))
            ++failed;
    }
    check_info("alias", CryptFindOIDInfo(CRYPT_OID_INFO_NAME_KEY, (void *)L"sha",
            CRYPT_HASH_ALG_OID_GROUP_ID), szOID_OIWSEC_sha1, L"SHA1");
    ++checks;
    if (CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, (void *)"1.2.3.4.5.6.7.8.9.10", 0))
        ++failed;
    ++checks;
    if (CryptFindOIDInfo(0, NULL, 0))
        ++failed;
    printf("OID metadata: %u checks, %u failures\n", checks, failed);
    return !!failed;
}
