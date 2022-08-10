package APNIC::RPKI::OpenSSL;

use warnings;
use strict;

use File::Slurp qw(read_file);
use File::Temp;
use Net::CIDR::Set;
use Set::IntSpan;

use APNIC::RPKI::Utils qw(system_ad);

our $VERSION = '0.1';

sub new
{
    my $class = shift;

    my %args = @_;
    my $self = \%args;

    if (not $self->{'path'}) {
        $self->{'path'} = "/usr/local/ssl/bin/openssl";
    }

    bless $self, $class;
    return $self;
}

sub get_openssl_path
{
    my ($self) = @_;

    return $self->{'path'};
}

sub verify_cms
{
    my ($self, $input, $ca_cert) = @_;

    my $ft_input = File::Temp->new();
    print $ft_input $input;
    $ft_input->flush();
    my $fn_input = $ft_input->filename();

    my $ft_ca = File::Temp->new();
    print $ft_ca $ca_cert;
    $ft_ca->flush();
    my $fn_ca = $ft_ca->filename();

    my $ft_output = File::Temp->new();
    my $fn_output = $ft_output->filename();

    my $openssl = $self->get_openssl_path();
    system_ad("$openssl cms -verify -partial_chain -inform DER ".
              "-in $fn_input ".
              "-CAfile $fn_ca ".
              "-out $fn_output",
              $self->{'debug'});

    return read_file($fn_output);
}

sub get_key_ski
{
    my ($self, $key) = @_;

    my $ft_key = File::Temp->new();
    print $ft_key $key;
    $ft_key->flush();
    my $fn_key = $ft_key->filename();

    my $openssl = $self->get_openssl_path();
    my ($ski) = `$openssl rsa -in $fn_key -pubout | openssl asn1parse -strparse 19 -noout -out - | openssl dgst -c -sha1`;
    $ski =~ s/.* //;
    $ski =~ s/://g;
    $ski = uc $ski;
    chomp $ski;
    return $ski;
}

sub get_ski
{
    my ($self, $cert) = @_;

    my $ft_cert = File::Temp->new();
    print $ft_cert $cert;
    $ft_cert->flush();
    my $fn_cert = $ft_cert->filename();

    my $openssl = $self->get_openssl_path();
    my (undef, $ski) = `$openssl x509 -in $fn_cert -text -noout | grep -A1 'Subject Key Identifier'`;
    $ski =~ s/\s*//g;
    $ski =~ s/://g;
    $ski = uc $ski;
    return $ski;
}

sub get_sias
{
    my ($self, $cert) = @_;

    my $ft_cert = File::Temp->new();
    print $ft_cert $cert;
    $ft_cert->flush();
    my $fn_cert = $ft_cert->filename();

    my $openssl = $self->get_openssl_path();
    my @lines = `$openssl x509 -in $fn_cert -text -noout`;
    my $flag = 0;
    my @sias;
    for my $line (@lines) {
        if (not $flag) {
            if ($line =~ /^\s*Subject Information Access:/) {
                $flag = 1;
                next;
            }
        } elsif ($line =~ /^                [^\s]/) {
            $line =~ s/^\s*//;
            my ($oid, $value) = ($line =~ /^(.*?) - (.*)$/);
            push @sias, [$oid, $value];
        } else {
            last;
        }
    }

    return \@sias;
}

sub get_crldps
{
    my ($self, $cert) = @_;

    my $ft_cert = File::Temp->new();
    print $ft_cert $cert;
    $ft_cert->flush();
    my $fn_cert = $ft_cert->filename();

    my $openssl = $self->get_openssl_path();
    my @crls = `$openssl x509 -in $fn_cert -text -noout | grep -A10 'CRL Distribution Points' | grep '\\.crl'`;
    my @final_crls;
    for my $crl (@crls) {
        $crl =~ s/\s*//g;
        $crl =~ s/.*?://;
        push @final_crls, $crl;
    }
    return \@crls;
}

sub get_aias
{
    my ($self, $cert) = @_;

    my $ft_cert = File::Temp->new();
    print $ft_cert $cert;
    $ft_cert->flush();
    my $fn_cert = $ft_cert->filename();

    my $openssl = $self->get_openssl_path();
    my @aias = `$openssl x509 -in $fn_cert -text -noout | grep 'CA Issuers.*rsync.*\\.cer'`;
    my @final_aias;
    for my $aia (@aias) {
        $aia =~ s/\s*//g;
        $aia =~ s/.*?://;
        push @final_aias, $aia;
    }
    return \@aias;
}

sub get_resources_strings
{
    my ($self, $cert) = @_;

    my $ft_cert = File::Temp->new();
    print $ft_cert $cert;
    $ft_cert->flush();
    my $fn_cert = $ft_cert->filename();

    my $openssl = $self->{'path'};
    my @data = `$openssl x509 -in $fn_cert -text -noout 2>/dev/null`;

    my @ipv4_strings;
    my @ipv6_strings;
    my @as_strings;

    for (my $i = 0; $i < @data; $i++) {
        my $line = $data[$i];
        if ($line =~ /sbgp-autonomousSysNum: critical/) {
            $i++;
            $i++;
            while ($line ne "") {
                $line = $data[$i++];
                $line =~ s/\s*//g;
                if ($line) {
                    push @as_strings, $line;
                }
            }
        }
    }
    for (my $i = 0; $i < @data; $i++) {
        my $line = $data[$i];
        if ($line =~ /sbgp-ipAddrBlock: critical/) {
            $i++;
            while ($line ne "") {
                $line = $data[$i++];
                $line =~ s/\s*//g;
                if ($line =~ /IPv4:\s*inherit/) {
                    push @ipv4_strings, "inherit";
                } elsif ($line =~ /IPv6:\s*inherit/) {
                    push @ipv6_strings, "inherit";
                } elsif ($line =~ /IPv/) {
                    next;
                } elsif ($line =~ /\./) {
                    push @ipv4_strings, $line;
                } elsif ($line =~ /:/) {
                    push @ipv6_strings, $line;
                }
            }
        }
    }

    return [ \@ipv4_strings, \@ipv6_strings, \@as_strings ];
}

sub is_inherit
{
    my ($self, $cert) = @_;

    my ($ipv4_strs, $ipv6_strs, $asn_strs) =
        @{$self->get_resources_strings($cert)};

    return ((@{$ipv4_strs} == 1)
            and ($ipv4_strs->[0] eq 'inherit')
            and (@{$ipv6_strs} == 1)
            and ($ipv6_strs->[0] eq 'inherit')
            and (@{$asn_strs} == 1)
            and ($asn_strs->[0] eq 'inherit'));
}

sub get_resources
{
    my ($self, $cert) = @_;

    my ($ipv4_strs, $ipv6_strs, $asn_strs) =
        @{$self->get_resources_strings($cert)};

    my $ipv4_set = Net::CIDR::Set->new({ type => 'ipv4' });
    my $ipv6_set = Net::CIDR::Set->new({ type => 'ipv6' });
    my $as_set = Set::IntSpan->new();

    for my $ipv4_str (@{$ipv4_strs}) {
        $ipv4_set->add($ipv4_str);
    }
    for my $ipv6_str (@{$ipv6_strs}) {
        $ipv6_set->add($ipv6_str);
    }
    for my $asn_str (@{$asn_strs}) {
        $as_set = $as_set->union($asn_str);
    }

    return [ $ipv4_set, $ipv6_set, $as_set ];
}

1;
