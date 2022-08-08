#!/usr/bin/perl

use warnings;
use strict;

use APNIC::RPKI::ASPA;
use APNIC::RPKI::Manifest;
use APNIC::RPKI::OpenSSL;
use File::Slurp qw(read_file);

use Test::More tests => 1;

{
    my $aspa_data = read_file('./t/objects/AS65000.asa.object');
    my $aspa = APNIC::RPKI::ASPA->new();
    $aspa->decode($aspa_data);

    my $aspa2 = APNIC::RPKI::ASPA->new();
    $aspa2->decode($aspa->encode());
    ok($aspa->equals($aspa2), 'ASPA decoded/encoded successfully');
}

{
    my $mft_data = read_file('./t/objects/mBQsnQtBo7n7YD12mEgjb9HzGSQ.mft.object');
    my $mft = APNIC::RPKI::Manifest->new();
    $mft->decode($mft_data);

    my $mft2 = APNIC::RPKI::Manifest->new();
    $mft2->decode($mft->encode());
    ok($mft->equals($mft2), 'Manifest decoded/encoded successfully');
}

1;
