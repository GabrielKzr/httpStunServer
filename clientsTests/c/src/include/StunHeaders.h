#ifndef STUNHEADERS_H
#define STUNHEADERS_H

#include <stdint.h>

#define MAGIC_COOKIE 0x2112A442 // Magic Cookie do STUN utilizado para criptografar ip
                                // para não haver possíveis bloqueios de transmissão por firewals ao detectarem ip exposto

typedef struct {
    uint16_t type;       // Sempre 0x0020 (XOR-MAPPED-ADDRESS)
    uint16_t length;     // 8 bytes para IPv4, 20 para IPv6
    uint8_t reserved;    // Sempre 0x00
    uint8_t family;      // 0x01 = IPv4, 0x02 = IPv6
    uint16_t xor_port;   // Porta codificada via XOR
    uint32_t xor_ip;     // IP codificado via XOR (IPv4)
} XorMappedAddress;

// Estrutura do cabeçalho STUN (28 bytes fixos (2 bytes de padding))
typedef struct {
    uint16_t type;           // Tipo da mensagem STUN
    uint16_t length;         // Tamanho total dos atributos
    uint32_t magic_cookie;   // Sempre 0x2112A442
    uint8_t uuid[16]; // ID único de dispositivo
    uint8_t transaction_id[12]; // ID único para rastrear mensagens
} StunHeader;

#endif