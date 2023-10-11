#!/usr/bin/env perl
package CryptoKi::CBC;

use strict;
use warnings;
use vars qw($VERSION);
use Data::Dumper;
use Crypt::Mode::CBC;

$VERSION = '1.0';

# Default initialization vector
use constant HEX_IV => '0' x 32;

# KIc: Ciphering Key Identifier
# K4: Transport Key
sub decode_kic {
    my ($i_hex_kic, $i_hex_k4, $i_hex_iv) = @_;

    
    my $bin_kic = pack('H*', $i_hex_kic);
    my $bin_k4 = pack('H*', $i_hex_k4);
    my $bin_iv = pack('H*', $i_hex_iv);

    my $cbc = Crypt::Mode::CBC->new('AES', 0); # 0 = no padding

    my $bin_ki = $cbc->decrypt($bin_kic, $bin_k4, $bin_iv);
    my $hex_ki = uc(unpack("H*", $bin_ki));

    $hex_ki;
}

# K4: Transport Key
# KI: Key Identifier
sub encode_ki {
    my ($i_hex_ki, $i_hex_k4, $i_hex_iv) = @_;

    
    my $bin_kic = pack('H*', $i_hex_ki);
    my $bin_k4 = pack('H*', $i_hex_k4);
    my $bin_iv = pack('H*', $i_hex_iv);

    my $cbc = Crypt::Mode::CBC->new('AES', 0); # 0 = no padding

    my $bin_ki = $cbc->encrypt($bin_kic, $bin_k4, $bin_iv);
    my $hex_kic = uc(unpack("H*", $bin_ki));

    $hex_kic;
}

# OPc: Operator code
sub generate_opc {
    my ($i_hex_ki, $i_hex_op, $i_hex_iv) = @_;

    my $bin_ki = pack('H*', $i_hex_ki);
    my $bin_op = pack('H*', $i_hex_op);
    my $bin_iv = pack('H*', $i_hex_iv);

    my $cbc = Crypt::Mode::CBC->new('AES', 0); # 0 = no padding

    my $encrypted_op = $cbc->encrypt($bin_op, $bin_ki, $bin_iv);
    my @encrypted_op_bytes = unpack("C16", $encrypted_op);
    my @opc_bytes = unpack("C16", $bin_op);

    for my $i (0 .. $#opc_bytes) {
        $opc_bytes[$i] ^= $encrypted_op_bytes[$i];
    }

    my $bin_opc = pack("C16", @opc_bytes);
    my $hex_opc = uc(unpack("H*", $bin_opc));

    $hex_opc;
}

1;
