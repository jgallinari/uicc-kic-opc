#!/usr/bin/env perl

use strict;
use warnings;
use Crypt::Digest::SHA512_256 qw( sha512_256_hex );
use FindBin qw($RealBin);
use lib "$RealBin/../lib";
use CryptoKi;

# Initialization vector
use constant HEX_IV => '0' x 32;

use constant OEM_PROD_K4 => sha512_256_hex(rand(100)); # 64 hex = 32 bytes = 256 bits
use constant OEM_PROD_OP => sha512_256_hex(rand(100)); # 64 hex = 32 bytes = 256 bits

my $hex_kic = 'FBE8C170F6A5C6C257E5324719674818';
my $hex_ki = CryptoKi::decode_kic($hex_kic, OEM_PROD_K4, HEX_IV);
my $hex_opc = CryptoKi::generate_opc($hex_ki, OEM_PROD_OP, HEX_IV);

print "KIc = $hex_kic, KI = $hex_ki, OPc = $hex_opc\n";

# Decrypt KIc w/ openssl
# echo -n "<KI>" | xxd -r -p | openssl enc -nopad -aes-256-cbc -d -iv 00000000000000000000000000000000 -K <TK> | hexdump -e '16/1 "%02x"'
