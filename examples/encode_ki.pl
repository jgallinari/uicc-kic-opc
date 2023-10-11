#!/usr/bin/env perl

use strict;
use warnings;
use Crypt::Digest::SHA512_256 qw( sha512_256_hex );
use FindBin qw($RealBin);
use lib "$RealBin/../lib";
use CryptoKi::CBC;

# Initialization vector
use constant HEX_IV => '0' x 32; # 32 hex = 16 bytes = 128 bits

use constant OEM_PROD_K4 => sha512_256_hex(rand(100)); # 64 hex = 32 bytes = 256 bits

my $hex_ki_cbc = 'C9118647A246DACDBD6A79437430B1B732F9473754E31C0FEA8F4B046D57F9AF';
my $hex_kic = CryptoKi::CBC::encode_ki($hex_ki_cbc, OEM_PROD_K4, HEX_IV);

print <<"EOF"
KI_CBC  = $hex_ki_cbc
KIc     = $hex_kic
EOF
