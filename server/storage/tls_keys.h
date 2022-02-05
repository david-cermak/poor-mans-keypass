#pragma once
#include <utility>
namespace tls_keys {

using  const_buf=std::pair<const unsigned char*, std::size_t>;

const_buf get_ca_cert();
const_buf get_server_cert();
const_buf get_server_key();
const_buf get_master_key();

}