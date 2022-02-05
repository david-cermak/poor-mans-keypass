#pragma once
#include "common_types.h"

namespace tls_keys {

const_buf get_ca_cert();
const_buf get_server_cert();
const_buf get_client_cert();
const_buf get_server_key();
const_buf get_client_key();
const_buf get_master_key();

}