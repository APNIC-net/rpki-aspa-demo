#!/usr/bin/perl

use warnings;
use strict;

use File::Slurp qw(write_file);
use File::Temp qw(tempdir);

use APNIC::RPKI::CA;
use APNIC::RPKI::ASPA;

{
    my $cas = tempdir(UNLINK => 1);
    print "$cas\n";
    system("mkdir -p $cas/ta");
    my $ca_path = "$cas/ta";
    my $ca = APNIC::RPKI::CA->new(ca_path => $ca_path);
    $ca->initialise('ta');
    $ca->publish();

    my $aspa_obj = APNIC::RPKI::ASPA->new();
    $aspa_obj->version(0);
    $aspa_obj->customer_asn(1024);
    $aspa_obj->providers([{
        provider_asn => 1025
    }]);
    my $aspa_data = $ca->sign_cms_aspa($aspa_obj->encode());
    write_file("stg-repo/an-object.asa", $aspa_data);
    $ca->publish();

    chdir $cas or die $!;
    mkdir 'cas' or die $!;
    system("mv ta cas/");

    my $cas2 = $cas;
    $cas2 =~ s/\//\\\//g;
    print("sed -i 's/path = .*/path = $cas2/' /etc/rsyncd.conf");
    print "\n";
    system("sed -i 's/path = .*/path = $cas2/' /etc/rsyncd.conf");
    system("/etc/init.d/rsync restart");

    my @pkey = `openssl x509 -in cas/ta/ca/ca.crt -noout -pubkey`;
    shift @pkey;
    pop @pkey;

    open my $fh, '>', '/home/tomh/rcynic/rpki-client-aspa-demo/tals/test.tal' or die $!;
    print $fh 'rsync://localhost/repo/cas/ta/ca/ca.der.cer'."\n\n";
    print $fh @pkey;
    close $fh;

    getc();
}

1;
