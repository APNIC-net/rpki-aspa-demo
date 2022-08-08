package APNIC::RPKI::CMS;

use warnings;
use strict;

use APNIC::RPKI::OpenSSL;

use File::Temp;

sub new
{
    my $class = shift;
    my $self = { openssl => APNIC::RPKI::OpenSSL->new() };
    bless $self, $class;
    return $self;
}

sub decode
{
    my ($self, $cms) = @_;

    my $ft = File::Temp->new();
    print $ft $cms;
    $ft->flush();
    my $fn = $ft->filename();

    my $openssl = $self->{'openssl'}->{'path'};
    my @output =
        map { chomp; $_ }
            `$openssl cms -in $fn -verify -noverify -print -inform DER -cmsout`;

    my @skis;
    for (my $i = 0; $i < @output; $i++) {
        if ($output[$i] ne '    signerInfos:') {
            next;
        }
        $i++;
        for (; $i < @output; $i++) {
            if ($output[$i] =~ /d\.subjectKeyIdentifier/) {
                $i++;
                my @ski_lines;
                for (; $i < @output; $i++) {
                    if ($output[$i] =~ /^ {10}/) {
                        push @ski_lines, $output[$i];
                    } else {
                        last;
                    }
                }
                for my $line (@ski_lines) {
                    $line =~ s/^.{17}//;
                    $line =~ s/   .*$//;
                }
                my $ski = join '', @ski_lines;
                $ski =~ s/ //g;
                $ski =~ s/-//g;
                $ski = uc $ski;
                push @skis, $ski;
            }
        }
    }

    return { skis => \@skis };
}

1;
