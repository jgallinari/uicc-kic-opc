#!/usr/bin/env perl

use strict;
use warnings;
use Crypt::Digest::SHA512_256 qw( sha512_256_hex );
use FindBin qw($RealBin);
use lib "$RealBin/../lib";
use CryptoKi::CBC;
use CryptoKi::ECB;

# Initialization vector
use constant HEX_IV => '0' x 32;

use constant OEM_PROD_K4 => sha512_256_hex(rand(100)); # 64 hex = 32 bytes = 256 bits
use constant OEM_PROD_OP => sha512_256_hex(rand(100)); # 64 hex = 32 bytes = 256 bits

# my $hex_kic = 'FBE8C170F6A5C6C257E5324719674818';
my $hex_kic = 'FBE8C170F6A5C6C257E5324719674818FBE8C170F6A5C6C257E5324719674818';
my $hex_ki_cbc = CryptoKi::CBC::decode_kic($hex_kic, OEM_PROD_K4, HEX_IV);
my $hex_opc = CryptoKi::CBC::generate_opc($hex_ki_cbc, OEM_PROD_OP, HEX_IV);
my $hex_ki_ecb = CryptoKi::ECB::decode_kic($hex_kic, OEM_PROD_K4);

print <<"EOF"
OEM_PROD_K4 = @{[OEM_PROD_K4]}
KIc    = $hex_kic
KI_CBC = $hex_ki_cbc
KI_ECB = $hex_ki_ecb
OPc    = $hex_opc
EOF

# Decrypt KIc w/ openssl
# echo -n "<KI>" | xxd -r -p | openssl enc -nopad -aes-256-cbc -d -iv 00000000000000000000000000000000 -K <TK> | hexdump -e '16/1 "%02x"'
