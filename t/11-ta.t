#!/usr/bin/perl

use warnings;
use strict;

use File::Slurp qw(write_file read_file);
use File::Temp qw(tempdir);

use APNIC::RPKI::CA;
use APNIC::RPKI::ASPA;

use Test::More tests => 4;

sub debug
{
    if ($ENV{'APNIC_DEBUG'}) {
        for my $msg (@_) {
            print STDERR $msg."\n";
        }
    }
}

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

    my $ca_path = "$cas/ta";
    mkdir $ca_path or die $!;
    my $ca = APNIC::RPKI::CA->new(ca_path => $ca_path);
    eval {
        $ca->initialise('ta', 0, $stg_repo_dir, $repo_dir,
                        'localhost', $port);
        $ca->publish();
    };
    my $error = $@;
    if ($error) {
        diag $error;
    }
    ok((not $error), "Initialised TA successfully");

    eval {
        my $aspa_obj = APNIC::RPKI::ASPA->new();
        $aspa_obj->version(1);
        $aspa_obj->customer_asn(1024);
        $aspa_obj->providers([1025]);
        my $aspa_data =
            $ca->issue_aspa($aspa_obj,
                "rsync://localhost:$port/ta/an-object.asa");
        $ca->publish_file("an-object.asa", $aspa_data);
        $ca->publish();
    };
    $error = $@;
    if ($error) {
        diag $error;
    }
    ok((not $error), "Published ASPA under TA");

    my $rpki_client_dir = tempdir(UNLINK => 1);
    chdir $rpki_client_dir or die $!;
    for my $dir (qw(cache output tals)) {
        mkdir $dir or die $!;
    }
    debug("rpki-client validator directory is $rpki_client_dir");

    my $ca_cert_pem = $ca->get_ca_pem();
    my $ca_cert_ft = File::Temp->new();
    my $ca_cert_fn = $ca_cert_ft->filename();
    write_file($ca_cert_fn, "-----BEGIN CERTIFICATE-----\n".
                            $ca_cert_pem."\n".
                            "-----END CERTIFICATE-----");
    my @ca_cert_pkey = `openssl x509 -in $ca_cert_fn -noout -pubkey`;
    shift @ca_cert_pkey;
    pop @ca_cert_pkey;
    my $ta_url = $ca->get_cert_rsync_url();
    my $tal_data = <<EOF;
$ta_url

@ca_cert_pkey
EOF
    write_file("$rpki_client_dir/tals/test.tal", $tal_data);

    # Download the repository manually and pass the -n flag to
    # rpki-client, because the cache directory will have the form
    # localhost:$port, and rsync will interpret that destination as a
    # remote host and refuse to run.
    chdir $rpki_client_dir or die $!;
    chdir "cache";
    mkdir $host_and_port or die $!;
    chdir $host_and_port or die $!;
    mkdir "repo" or die $!;
    chdir "repo" or die $!;
    system("rsync -az rsync://$host_and_port/repo/* .");
    chdir $rpki_client_dir or die $!;
    $res = system("/usr/local/bin/rpki-client -n -c -t tals/test.tal -d cache output");
    ok(($res == 0),
        'rpki-client validated the TA successfully');

    my $pid = read_file($pid_file_fn);
    chomp $pid;
    kill 9, $pid;
}

1;
