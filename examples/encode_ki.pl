#!/usr/bin/env perl

use strict;
use warnings;
use Crypt::Digest::SHA512_256 qw( sha512_256_hex );
use FindBin qw($RealBin);
use lib "$RealBin/../lib";
use CryptoKi;

# Initialization vector
use constant HEX_IV => '0' x 32; # 32 hex = 16 bytes = 128 bits

use constant OEM_PROD_K4 => sha512_256_hex(rand(100)); # 64 hex = 32 bytes = 256 bits

my $hex_ki = '8978B79E7C104F678FA5C336509DB188';
my $hex_kic = CryptoKi::encode_ki($hex_ki, OEM_PROD_K4, HEX_IV);
print "KI = $hex_ki, KIc = $hex_kic\n";
