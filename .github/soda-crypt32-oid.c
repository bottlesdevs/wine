#define CRYPT_OID_INFO_HAS_EXTRA_FIELDS
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <wchar.h>

int main(void)
{
    static const struct
    {
        const char *oid;
        DWORD group;
        const WCHAR *cng;
    } tests[] =
    {
        {szOID_RSA_MD2, CRYPT_HASH_ALG_OID_GROUP_ID, L"MD2"},
        {szOID_RSA_MD4, CRYPT_HASH_ALG_OID_GROUP_ID, L"MD4"},
        {szOID_RSA_MD5, CRYPT_HASH_ALG_OID_GROUP_ID, L"MD5"},
        {szOID_OIWSEC_sha1, CRYPT_HASH_ALG_OID_GROUP_ID, L"SHA1"},
        {szOID_NIST_sha256, CRYPT_HASH_ALG_OID_GROUP_ID, L"SHA256"},
        {szOID_NIST_sha384, CRYPT_HASH_ALG_OID_GROUP_ID, L"SHA384"},
        {szOID_NIST_sha512, CRYPT_HASH_ALG_OID_GROUP_ID, L"SHA512"}
    };
    unsigned int i, failed = 0;

    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
    {
        PCCRYPT_OID_INFO info = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY,
                (void *)tests[i].oid, tests[i].group);
        printf("oid=%s found=%u", tests[i].oid, (unsigned int)!!info);
        if (info)
        {
            printf(" size=%lu algid=%#x cng=%ls extra=%ls", info->cbSize, info->Algid,
                    info->pwszCNGAlgid ? info->pwszCNGAlgid : L"<null>",
                    info->pwszCNGExtraAlgid ? info->pwszCNGExtraAlgid : L"<null>");
        }
        if (!info || !info->pwszCNGAlgid || wcscmp(info->pwszCNGAlgid, tests[i].cng) ||
                !info->pwszCNGExtraAlgid || *info->pwszCNGExtraAlgid)
            ++failed;
        putchar('\n');
    }
    printf("OID metadata: %u checks, %u failures\n", i, failed);
    return !!failed;
}
