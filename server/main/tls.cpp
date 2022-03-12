#include "tls.h"
#include "mbedtls/ctr_drbg.h"
#include "sys/socket.h"
#include "storage/tls_keys.h"

bool Tls::init(bool is_server, bool verify)
{
    const char pers[] = "mbedtls_wrapper";
    mbedtls_entropy_init(&entropy_);
    mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_, (const unsigned char *)pers, sizeof(pers));
    int ret = mbedtls_ssl_config_defaults(&conf_, is_server?MBEDTLS_SSL_IS_SERVER:MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret) {
        print_error("mbedtls_ssl_config_defaults", ret);
        return false;
    }
    mbedtls_ssl_conf_rng(&conf_, mbedtls_ctr_drbg_random, &ctr_drbg_);
    mbedtls_ssl_conf_authmode(&conf_, verify?MBEDTLS_SSL_VERIFY_REQUIRED:MBEDTLS_SSL_VERIFY_NONE);
    ret = mbedtls_ssl_conf_own_cert(&conf_, &public_cert_, &pk_key_);
    if (ret) {
        print_error("mbedtls_ssl_conf_own_cert", ret);
        return false;
    }
    if (verify) {
        mbedtls_ssl_conf_ca_chain(&conf_, &ca_cert_, nullptr);
    }
    ret = mbedtls_ssl_setup(&ssl_, &conf_);
    if (ret) {
        print_error("mbedtls_ssl_setup", ret);
        return false;
    }
    return true;
}

void Tls::print_error(const char *function, int error_code)
{
    static char error_buf[100];
    mbedtls_strerror(error_code, error_buf, sizeof(error_buf));

    printf("%s() returned -0x%04X", function, -error_code);
    printf("-0x%04X: %s", -error_code, error_buf);
}

int Tls::handshake(int s)
{
    sock_ = s;
    int ret = 0;
    mbedtls_ssl_set_bio(&ssl_, this, bio_write, bio_read, nullptr);

    while( ( ret = mbedtls_ssl_handshake( &ssl_ ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            print_error( "mbedtls_ssl_handshake returned", ret );
            return -1;
        }
    }
    return ret;
}

int Tls::bio_write(void *ctx, const unsigned char *buf, size_t len)
{
    auto s = static_cast<Tls*>(ctx);
    return s->send(buf, len);
}

int Tls::bio_read(void *ctx, unsigned char *buf, size_t len)
{
    auto s = static_cast<Tls*>(ctx);
    return s->recv(buf, len);
}

int Tls::write(const unsigned char *buf, size_t len)
{
    return mbedtls_ssl_write( &ssl_, buf, len );
}

int Tls::read(unsigned char *buf, size_t len)
{
    return mbedtls_ssl_read( &ssl_, buf, len );
}

bool Tls::set_own_cert(const_buf crt, const_buf key)
{
    int ret = mbedtls_x509_crt_parse(&public_cert_, crt.first, crt.second);
    if (ret < 0) {
        print_error("mbedtls_x509_crt_parse", ret);
        return false;
    }
    ret = mbedtls_pk_parse_key(&pk_key_, key.first, key.second, nullptr, 0);
    if (ret < 0) {
        print_error("mbedtls_pk_parse_keyfile", ret);
        return false;
    }
    return true;
}

bool Tls::set_ca_cert(const_buf crt)
{
    int ret = mbedtls_x509_crt_parse(&ca_cert_, crt.first, crt.second);
    if (ret < 0) {
        print_error("mbedtls_x509_crt_parse", ret);
        return false;
    }
    return true;
}

Tls::Tls()
{
    mbedtls_x509_crt_init(&public_cert_);
    mbedtls_pk_init(&pk_key_);
    mbedtls_pk_init(&master_key_);
    mbedtls_x509_crt_init(&ca_cert_);
}

int Tls::recv(unsigned char *buf, size_t len)
{
    printf("Try to read %d\n", len);
    int l = ::recv(sock_, buf, len, 0);
    for (int i=0; i<l; ++i)
        printf("0x%0x, ", buf[i]);
    printf("\nReading %d\n",l);
    return l;

}

int Tls::send(const unsigned char *buf, size_t len)
{
    for (int i=0; i<len; ++i)
        printf("0x%0x, ", buf[i]);
    int l = ::send(sock_, buf, len, 0);
    printf("\nWriting %d\n", l);
    return l;
}

int
Tls::mbedtls_pk_parse_key(mbedtls_pk_context *ctx, const unsigned char *key, size_t keylen, const unsigned char *pwd,
                          size_t pwdlen) {

    return ::mbedtls_pk_parse_key(ctx, key, keylen, pwd, pwdlen
//#ifndef ESP_PLATFORM
                                  , nullptr, nullptr
//#endif
    );
}

bool Tls::set_mater_key(const_buf key)
{
    int ret = mbedtls_pk_parse_key(&master_key_, key.first, key.second, nullptr, 0);
    if (ret < 0) {
        print_error("mbedtls_pk_parse_keyfile", ret);
        return false;
    }
    return true;
}

size_t Tls::decrypt(buf &in_buf, buf &out_buf)
{
    size_t out_size = 0;
    int ret = ::mbedtls_pk_decrypt( &master_key_, in_buf.first, in_buf.second,
                                  out_buf.first, &out_size, out_buf.second,
                                  mbedtls_ctr_drbg_random, &ctr_drbg_);
    if (ret < 0) {
        return -1;
    }
    return out_size;
}

