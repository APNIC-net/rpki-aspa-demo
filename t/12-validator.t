#!/usr/bin/perl

use warnings;
use strict;

use File::Slurp qw(write_file read_file);
use File::Temp qw(tempdir);

use APNIC::RPKI::CA;
use APNIC::RPKI::ASPA;
use APNIC::RPKI::Validator;

use Test::More tests => 12;

sub debug
{
    if ($ENV{'APNIC_DEBUG'}) {
        for my $msg (@_) {
            print STDERR $msg."\n";
        }
    }
}

my $pid;

sub _tempdir
{
    my @params =
        ($ENV{'APNIC_DEBUG'}) ? () : (UNLINK => 1);
    return tempdir(@params);
}

{
    my $cas = _tempdir();
    my $stg_repo_dir = _tempdir();
    my $repo_dir = _tempdir();
    debug("CA directory is $cas");
    debug("Staging repository directory is $stg_repo_dir");
    debug("Repository directory is $repo_dir");

    my $pid_file = File::Temp->new();
    my $pid_file_fn = $pid_file->filename();
    my $port = ($$ % (65536 - 1024)) + 1024;

    my $conf = <<EOF;
use chroot = no
max connections = 0
max verbosity = 4
syslog facility = local5
pid file = $pid_file_fn
port = $port

[repo]
       path = $repo_dir
       comment = RPKI repository
       exclude = .*
EOF

    my $rsync_conf_file = File::Temp->new();
    my $rsync_conf_file_fn = $rsync_conf_file->filename();
    write_file($rsync_conf_file_fn, $conf);
    debug("rsync daemon configuration file is $rsync_conf_file_fn");

    system("rsync --daemon --config=$rsync_conf_file_fn");
    my $host_and_port = "localhost:$port";
    my $res = system("rsync rsync://$host_and_port/ >/dev/null 2>&1");
    ok(($res == 0), 'Started rsync server successfully');
    $pid = read_file($pid_file_fn);
    chomp $pid;

    my $ca_path = "$cas/ta";
    mkdir $ca_path or die $!;
    my $ca = APNIC::RPKI::CA->new(ca_path => $ca_path);
    eval {
        $ca->initialise('ta', 0, $stg_repo_dir, $repo_dir,
                        'localhost', $port, undef, [1000]);
        $ca->publish();
    };
    my $error = $@;
    if ($error) {
        diag $error;
    }
    ok((not $error), "Initialised TA successfully");

    my $aspa_data;
    eval {
        my $aspa_obj = APNIC::RPKI::ASPA->new();
        $aspa_obj->version(1);
        $aspa_obj->customer_asn(100000);
        $aspa_obj->providers([1025]);
        $aspa_data = $ca->issue_aspa($aspa_obj,
            "rsync://localhost:$port/ta/an-object.asa");
        $ca->publish_file("an-object.asa", $aspa_data);
        $ca->publish();
    };
    $error = $@;
    if ($error) {
        diag $error;
    }
    ok((not $error), "Published invalid ASPA under TA (wrong ASN)");

    my $ca_cert = "-----BEGIN CERTIFICATE-----\n".
                  $ca->get_ca_pem()."\n".
                  "-----END CERTIFICATE-----";

    my $validator = APNIC::RPKI::Validator->new();
    $res = eval {
        $validator->validate_aspa(
            $aspa_data, [$ca_cert],
        );
    };
    $error = $@;
    like($error, qr/not subset of parent's resources/,
        "ASPA with uncertified ASN is invalid");

    eval {
        my $aspa_obj = APNIC::RPKI::ASPA->new();
        $aspa_obj->version(2);
        $aspa_obj->customer_asn(1000);
        $aspa_obj->providers([1025]);
        $aspa_data = $ca->issue_aspa($aspa_obj,
            "rsync://localhost:$port/ta/an-object.asa");
        $ca->publish_file("an-object.asa", $aspa_data);
        $ca->publish();
    };
    $error = $@;
    if ($error) {
        diag $error;
    }
    ok((not $error), "Published invalid ASPA under TA (wrong version)");

    $res = eval {
        $validator->validate_aspa(
            $aspa_data, [$ca_cert],
        );
    };
    $error = $@;
    like($error, qr/ASPA version is invalid/,
        "ASPA with invalid version is invalid");

    eval {
        my $aspa_obj = APNIC::RPKI::ASPA->new();
        $aspa_obj->version(1);
        $aspa_obj->customer_asn(1000);
        $aspa_obj->providers([1025, 1024]);
        $aspa_data = $ca->issue_aspa($aspa_obj,
            "rsync://localhost:$port/ta/an-object.asa");
        $ca->publish_file("an-object.asa", $aspa_data);
        $ca->publish();
    };
    $error = $@;
    if ($error) {
        diag $error;
    }
    ok((not $error), "Published invalid ASPA under TA ".
                     "(unordered providers)");

    $res = eval {
        $validator->validate_aspa(
            $aspa_data, [$ca_cert],
        );
    };
    $error = $@;
    like($error, qr/ASPA providers are not in order/,
        "ASPA with unordered providers is not valid");

    eval {
        my $aspa_obj = APNIC::RPKI::ASPA->new();
        $aspa_obj->version(1);
        $aspa_obj->customer_asn(1000);
        $aspa_obj->providers([1025, 1025]);
        $aspa_data = $ca->issue_aspa($aspa_obj,
            "rsync://localhost:$port/ta/an-object.asa");
        $ca->publish_file("an-object.asa", $aspa_data);
        $ca->publish();
    };
    $error = $@;
    if ($error) {
        diag $error;
    }
    ok((not $error), "Published invalid ASPA under TA ".
                     "(duplicate providers)");

    $res = eval {
        $validator->validate_aspa(
            $aspa_data, [$ca_cert],
        );
    };
    $error = $@;
    like($error, qr/ASPA contains duplicate provider ASN/,
        "ASPA with duplicate providers is not valid");

    eval {
        my $aspa_obj = APNIC::RPKI::ASPA->new();
        $aspa_obj->version(1);
        $aspa_obj->customer_asn(1000);
        $aspa_obj->providers([1025]);
        $aspa_data = $ca->issue_aspa($aspa_obj,
            "rsync://localhost:$port/ta/an-object.asa");
        $ca->publish_file("an-object.asa", $aspa_data);
        $ca->publish();
    };
    $error = $@;
    if ($error) {
        diag $error;
    }
    ok((not $error), "Published valid ASPA under TA");

    $res = eval {
        $validator->validate_aspa(
            $aspa_data, [$ca_cert],
        );
    };
    $error = $@;
    if ($error) {
        diag $error;
    }
    ok((not $error), "ASPA is valid");
}

END {
    kill 9, $pid;
}

1;
