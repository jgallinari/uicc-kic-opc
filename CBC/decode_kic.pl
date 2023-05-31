#!/usr/bin/env perl

use strict;
use warnings;
use Crypt::Mode::CBC;

# Initialization vector
use constant HEX_IV => '0' x 32;
use constant BIN_IV => pack("H*", HEX_IV);

use constant OEM_PROD_K4 => '2257CC6E9746434B89F346F0276CCAEC'; # 32 hex
use constant OEM_PROD_OP => 'D7DECB1F50404CC29ECBF989FE73AFC5'; # 32 hex

# K4: Transport Key
# KIc: Ciphering Key Identifier
sub decode_kic {
    my ($i_hex_k4, $i_hex_kic) = @_;

    
    my $bin_k4 = pack('H*', $i_hex_k4);
    my $bin_kic = pack('H*', $i_hex_kic);

    my $cbc = Crypt::Mode::CBC->new('AES', 0); # 0 = no padding

    my $bin_ki = $cbc->decrypt($bin_kic, $bin_k4, BIN_IV);
    my $hex_ki = uc(unpack("H*", $bin_ki));

    $hex_ki;
}

# OPc: Operator code
sub generate_opc {
    my ($i_hex_op, $i_hex_ki) = @_;

    my $bin_op = pack('H*', $i_hex_op);
    my $bin_ki = pack('H*', $i_hex_ki);

    my $cbc = Crypt::Mode::CBC->new('AES', 0); # 0 = no padding

    my $encrypted_op = $cbc->encrypt($bin_op, $bin_ki, BIN_IV);
    my @encrypted_op_bytes = unpack("C16", $encrypted_op);
    my @opc_bytes = unpack("C16", $bin_op);

    for my $i (0 .. $#opc_bytes) {
        $opc_bytes[$i] ^= $encrypted_op_bytes[$i];
    }

    my $bin_opc = pack("C16", @opc_bytes);
    my $hex_opc = uc(unpack("H*", $bin_opc));

    $hex_opc;
}

my $hex_kic = 'FBE8C170F6A5C6C257E5324719674818';
my $hex_ki = decode_kic(OEM_PROD_K4, $hex_kic);
my $hex_opc = generate_opc(OEM_PROD_OP, $hex_ki);

print "KIc = $hex_kic, KI = $hex_ki, OPc = $hex_opc\n";
