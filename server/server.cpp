#include "server.h"
#include "mbedtls/ctr_drbg.h"
#include "sys/socket.h"
#include "tls_keys.h"

bool server::init()
{
    const char pers[] = "rsa_decrypt";
    mbedtls_entropy_init(&entropy_);
    mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_, (const unsigned char *)pers, sizeof(pers));
    mbedtls_x509_crt_init(&public_cert_);
    mbedtls_pk_init(&pk_key_);
    mbedtls_x509_crt_init(&ca_cert_);
    int ret = mbedtls_ssl_config_defaults(&conf_, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret) {
        print_error("mbedtls_ssl_config_defaults", ret);
        return false;
    }
    mbedtls_ssl_conf_rng(&conf_, mbedtls_ctr_drbg_random, &ctr_drbg_);
    mbedtls_ssl_conf_authmode(&conf_, MBEDTLS_SSL_VERIFY_REQUIRED);
    auto server_crt = tls_keys::get_server_cert();
    ret = mbedtls_x509_crt_parse(&public_cert_, server_crt.first, server_crt.second);
    if (ret < 0) {
        print_error("mbedtls_x509_crt_parse", ret);
        return false;
    }
    auto server_key = tls_keys::get_server_key();
    ret = mbedtls_pk_parse_key(&pk_key_, server_key.first, server_key.second, nullptr, 0, mbedtls_ctr_drbg_random, &ctr_drbg_ );
    if (ret < 0) {
        print_error("mbedtls_pk_parse_keyfile", ret);
        return false;
    }
    ret = mbedtls_ssl_conf_own_cert(&conf_, &public_cert_, &pk_key_);
    if (ret) {
        print_error("mbedtls_ssl_conf_own_cert", ret);
        return false;
    }
    auto ca_crt = tls_keys::get_ca_cert();
    ret = mbedtls_x509_crt_parse(&ca_cert_, ca_crt.first, ca_crt.second);
    if (ret < 0) {
        print_error("mbedtls_x509_crt_parse", ret);
        return false;
    }
    mbedtls_ssl_conf_ca_chain(&conf_, &ca_cert_, nullptr);
    ret = mbedtls_ssl_setup(&ssl_, &conf_);
    if (ret) {
        print_error("mbedtls_ssl_setup", ret);
        return false;
    }
    return true;
}

void server::print_error(const char *function, int error_code)
{
    static char error_buf[100];
    mbedtls_strerror(error_code, error_buf, sizeof(error_buf));

    printf("%s() returned -0x%04X", function, -error_code);
    printf("-0x%04X: %s", -error_code, error_buf);
}

int server::handshake(int s)
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

int server::bio_write(void *ctx, const unsigned char *buf, size_t len)
{
    auto s = static_cast<server*>(ctx);
    return send(s->sock_, buf, len, 0);
}

int server::bio_read(void *ctx, unsigned char *buf, size_t len)
{
    auto s = static_cast<server*>(ctx);
    return recv(s->sock_, buf, len, 0);
}

int server::write(const unsigned char *buf, size_t len)
{
    return mbedtls_ssl_write( &ssl_, buf, len );
}

int server::read(unsigned char *buf, size_t len)
{
    return mbedtls_ssl_read( &ssl_, buf, len );
}
