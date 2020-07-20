#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <string>

#include "openssl/md5.h"
#include "openssl/sha.h"

#include "neonext.h"

const Ne_MethodTable *Ne;

inline char hex_digit(unsigned d)
{
    return static_cast<char>(d < 10 ? '0' + d : 'a' + (d - 10));
}

static std::string to_hex(const unsigned char *hash, int len)
{
    std::string r(2 * len, 'x');
    for (std::string::size_type i = 0; i < len; i++) {
        unsigned char b = hash[i];
        r[2*i] = hex_digit(b >> 4);
        r[2*i+1] = hex_digit(b & 0xf);
    }
    return r;
}

extern "C" {

Ne_EXPORT int Ne_INIT(const Ne_MethodTable *methodtable)
{
    Ne = methodtable;
    return Ne_SUCCESS;
}

Ne_FUNC(Ne_md5Raw)
{
    Ne_Bytes bytes = Ne_PARAM_BYTES(0);

    unsigned char buf[MD5_DIGEST_LENGTH];
    MD5(bytes.ptr, bytes.len, buf);
    Ne_RETURN_BYTES(buf, sizeof(buf));
}

Ne_FUNC(Ne_md5)
{
    Ne_Bytes bytes = Ne_PARAM_BYTES(0);

    unsigned char buf[MD5_DIGEST_LENGTH];
    MD5(bytes.ptr, bytes.len, buf);
    std::string hash = to_hex(buf, sizeof(buf));
    Ne_RETURN_BYTES(reinterpret_cast<const unsigned char *>(hash.data()), static_cast<int>(hash.length()));
}

Ne_FUNC(Ne_sha1Raw)
{
    Ne_Bytes bytes = Ne_PARAM_BYTES(0);

    unsigned char buf[SHA_DIGEST_LENGTH];
    SHA1(bytes.ptr, bytes.len, buf);
    Ne_RETURN_BYTES(buf, sizeof(buf));
}

Ne_FUNC(Ne_sha1)
{
    Ne_Bytes bytes = Ne_PARAM_BYTES(0);

    unsigned char buf[SHA_DIGEST_LENGTH];
    SHA1(bytes.ptr, bytes.len, buf);
    std::string hash = to_hex(buf, sizeof(buf));
    Ne_RETURN_BYTES(reinterpret_cast<const unsigned char *>(hash.data()), static_cast<int>(hash.length()));
}

Ne_FUNC(Ne_sha256Raw)
{
    Ne_Bytes bytes = Ne_PARAM_BYTES(0);

    unsigned char buf[SHA256_DIGEST_LENGTH];
    SHA256(bytes.ptr, bytes.len, buf);
    Ne_RETURN_BYTES(buf, sizeof(buf));
}

Ne_FUNC(Ne_sha256)
{
    Ne_Bytes bytes = Ne_PARAM_BYTES(0);

    unsigned char buf[SHA256_DIGEST_LENGTH];
    SHA256(bytes.ptr, bytes.len, buf);
    std::string hash = to_hex(buf, sizeof(buf));
    Ne_RETURN_BYTES(reinterpret_cast<const unsigned char *>(hash.data()), static_cast<int>(hash.length()));
}

Ne_FUNC(Ne_sha512Raw)
{
    Ne_Bytes bytes = Ne_PARAM_BYTES(0);

    unsigned char buf[SHA512_DIGEST_LENGTH];
    SHA512(bytes.ptr, bytes.len, buf);
    Ne_RETURN_BYTES(buf, sizeof(buf));
}

Ne_FUNC(Ne_sha512)
{
    Ne_Bytes bytes = Ne_PARAM_BYTES(0);

    unsigned char buf[SHA512_DIGEST_LENGTH];
    SHA512(bytes.ptr, bytes.len, buf);
    std::string hash = to_hex(buf, sizeof(buf));
    Ne_RETURN_BYTES(reinterpret_cast<const unsigned char *>(hash.data()), static_cast<int>(hash.length()));
}

} // extern "C"
