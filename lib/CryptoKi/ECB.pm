#!/usr/bin/env perl
package CryptoKi::ECB;

use strict;
use warnings;
use vars qw($VERSION);
use Data::Dumper;
use Crypt::Mode::ECB;

$VERSION = '1.0';

# KIc: Ciphering Key Identifier
# K4: Transport Key
sub decode_kic {
    my ($i_hex_kic, $i_hex_k4) = @_;

    
    my $bin_kic = pack('H*', $i_hex_kic);
    my $bin_k4 = pack('H*', $i_hex_k4);

    my $ecb = Crypt::Mode::ECB->new('AES', 0); # 0 = no padding

    my $bin_ki = $ecb->decrypt($bin_kic, $bin_k4);
    my $hex_ki = uc(unpack("H*", $bin_ki));

    $hex_ki;
}

# K4: Transport Key
# KI: Key Identifier
sub encode_ki {
    my ($i_hex_ki, $i_hex_k4) = @_;

    
    my $bin_kic = pack('H*', $i_hex_ki);
    my $bin_k4 = pack('H*', $i_hex_k4);

    my $ecb = Crypt::Mode::ECB->new('AES', 0); # 0 = no padding

    my $bin_ki = $ecb->encrypt($bin_kic, $bin_k4);
    my $hex_kic = uc(unpack("H*", $bin_ki));

    $hex_kic;
}

# OPc: Operator code
sub generate_opc {
    my ($i_hex_ki, $i_hex_op) = @_;

    my $bin_ki = pack('H*', $i_hex_ki);
    my $bin_op = pack('H*', $i_hex_op);

    my $ecb = Crypt::Mode::ECB->new('AES', 0); # 0 = no padding

    my $encrypted_op = $ecb->encrypt($bin_op, $bin_ki);
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
