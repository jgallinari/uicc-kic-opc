#!/usr/bin/env perl

use strict;
use warnings;
use Crypt::Mode::CBC;

# Initialization vector
use constant HEX_IV => '0' x 32;
use constant BIN_IV => pack("H*", HEX_IV);

use constant OEM_PROD_K4 => '2257CC6E9746434B89F346F0276CCAEC'; # 32 hex

# K4: Transport Key
sub encode_ki {
    my ($i_hex_k4, $i_hex_ki) = @_;

    my $bin_k4 = pack('H*', $i_hex_k4);
    my $bin_ki = pack("H*", $i_hex_ki);

    my $cbc = Crypt::Mode::CBC->new('AES', 0); # 0 = no padding

    my $bin_kic = $cbc->encrypt($bin_ki, $bin_k4, BIN_IV);
    my $hex_kic = uc(unpack("H*", $bin_kic));

    $hex_kic;
}

my $hex_ki = '8978B79E7C104F678FA5C336509DB188';
my $hex_kic = encode_ki(OEM_PROD_K4, $hex_ki);

print "KI = $hex_ki, KIc = $hex_kic\n";
