#!/usr/bin/perl

use warnings;
use strict;

use File::Temp qw(tempdir);

use APNIC::RPKI::CA;

{
    my $cas = tempdir(UNLINK => 1);
    print "$cas\n";
    system("mkdir -p $cas/ta");
    my $ca_path = "$cas/ta";
    my $ca = APNIC::RPKI::CA->new(ca_path => $ca_path);
    $ca->initialise('ta');
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
