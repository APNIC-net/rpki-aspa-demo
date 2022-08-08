package APNIC::RPKI::Utils;

use warnings;
use strict;

use File::Slurp qw(read_file);
use File::Temp;

use Exporter qw(import);

our @EXPORT_OK = qw(canonicalise_pem
                    system_ad);

sub canonicalise_pem
{
    my ($pem) = @_;

    $pem =~ s/\s*//g;
    $pem =~ s/(.{1,60})/$1\n/gs;
    chomp $pem;

    return $pem;
}

sub system_ad
{
    my ($cmd, $debug) = @_;

    my $output_ft = File::Temp->new();
    my $output_fn = $output_ft->filename();

    my $res = system($cmd.($debug ? "" : " >$output_fn 2>&1"));
    if ($res != 0) {
        print read_file($output_fn);
        die "Command execution failed.\n";
    }

    return 1;
}

1;
