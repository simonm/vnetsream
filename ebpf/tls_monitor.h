#ifndef TLS_MONITOR_H
#define TLS_MONITOR_H

#include <linux/types.h>

#define TLS_HANDSHAKE 22
#define TLS_CLIENT_HELLO 1
#define TLS_SERVER_HELLO 2
#define TLS_CERTIFICATE 11

struct flow_tuple {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u32  protocol;
};

struct tls_info {
    __u8  content_type;
    __u16 version;
    __u16 length;
    __u8  handshake_type;
    __u32 handshake_len;
    __u8  is_certificate: 1;
    __u8  is_client_hello: 1;
    __u8  is_server_hello: 1;
    __u8  needs_reassembly: 1;
};

struct cert_metadata {
    __u32 chain_id;
    __u16 cert_length;
    __u16 chain_position;
    __u8  is_ca: 1;
    __u8  is_last: 1;
    __u8  data[0];
};

struct stream_state {
    __u32 last_seq;
    __u32 bytes_expected;
    __u8  handshake_type;
    __u8  processing_certs: 1;
};

#endif /* TLS_MONITOR_H */
