package APNIC::RPKI::Validator;

use warnings;
use strict;

use APNIC::RPKI::CMS;
use APNIC::RPKI::OpenSSL;
use APNIC::RPKI::Utils qw(system_ad);
use File::Basename qw(basename);
use File::Slurp qw(read_file);
use File::Temp qw(tempdir);
use Digest::SHA qw(sha256_hex);
use Net::CIDR::Set;
use Set::IntSpan;

sub new
{
    my ($class, $openssl) = @_;
    $openssl ||= APNIC::RPKI::OpenSSL->new();
    my $self = { openssl => $openssl };
    bless $self, $class;
    return $self;
}

sub get_resources_from_cert
{
    my ($self, $cert) = @_;

    my $openssl = $self->{'openssl'};
    if ($openssl->is_inherit($cert)) {
        my @aias = @{$openssl->get_aias($cert)};
        if (@aias > 1) {
            die "Expected single AIA";
        }
        my $aia = $aias[0];
        my $ft = File::Temp->new();
        my $fn = $ft->filename();
        system_ad("rsync $aia $fn");
        system_ad("openssl x509 -inform DER -outform PEM -in $fn -out $fn.pem");
        my $aia_cert = read_file("$fn.pem");
        my $cert_ski = $openssl->get_ski($cert);
        my $aia_cert_ski = $openssl->get_ski($aia_cert);
        if ($cert_ski eq $aia_cert_ski) {
            die "Could not find resources: ".
                "certificate is inherit, but ".
                "AIA points to self";
        }
        return $self->get_resources_from_cert($aia_cert);
    }

    my $resources = $openssl->get_resources($cert);
    return $resources;
}

sub validate_aspa
{
    my ($self, $aspa_raw, $ta, $certs_only) = @_;

    my $openssl = $self->{'openssl'}->{'path'};

    my $ft = File::Temp->new();
    print $ft $aspa_raw;
    $ft->flush();
    my $fn = $ft->filename();

    my $certs_ft = File::Temp->new();
    my $certs_fn = $certs_ft->filename();
    system("$openssl cms -inform DER -in $fn -verify -noverify -certsout $certs_fn >/dev/null 2>&1");
    my @lines = read_file($certs_fn);
    my @certs;
    my @current_cert_lines;
    for my $line (@lines) {
        chomp $line;
        if ($line eq '-----BEGIN CERTIFICATE-----') {
            if (@current_cert_lines) {
                die "Failed to parse certificates";
            }
            push @current_cert_lines, $line;
        } elsif ($line eq '-----END CERTIFICATE-----') {
            push @current_cert_lines, $line;
            push @certs, (join "\n", @current_cert_lines);
            @current_cert_lines = ();
        } elsif (@current_cert_lines) {
            push @current_cert_lines, $line;
        } else {
            print "($line)\n";
            die "Failed to parse certificates (2)";
        }
    }

    if (not @certs) {
        die "No certificates found";
    }

    # Get the EE certificate;

    my $ee_cert;
    for my $cert (@certs) {
        my $cft = File::Temp->new();
        print $cft $cert;
        $cft->flush();
        my $cft_fn = $cft->filename();

        my @data = `$openssl x509 -in $cft_fn -text -noout`;
        if (grep { /CA:TRUE/ } @data) {
            next;
        }
        if (defined $ee_cert) {
            die "Expected one EE certificate, ".
                "but found multiple";
        }
        $ee_cert = $cert;
    }
    if (not $ee_cert) {
        die "No EE certificate found in ASPA";
    }
    my $resources = $self->get_resources_from_cert($ee_cert);
    my ($ipv4_set, $ipv6_set, $as_set) = @{$resources};

    my @certs_to_check = @certs;
    my @extra_certs;
    my @extra_crls;
    while (@certs_to_check) {
        my $cert = pop @certs_to_check;
        my $aias = $self->{'openssl'}->get_aias($cert);
        for my $aia (@{$aias}) {
            my $ft = File::Temp->new();
            my $fn = $ft->filename();
            system_ad("rsync $aia $fn");
            my $ft_pem = File::Temp->new();
            my $fn_pem = $ft_pem->filename();
            system_ad("$openssl x509 -inform DER -in $fn -outform PEM -out $fn_pem > /dev/null 2>&1");
            my @lines = read_file("$fn_pem");
            my $new_cert = join "", @lines;
            push @extra_certs, $new_cert;
            push @certs_to_check, $new_cert;
        }
        my $crldps = $self->{'openssl'}->get_crldps($cert);
        for my $crldp (@{$crldps}) {
            my $ft = File::Temp->new();
            my $fn = $ft->filename();
            system_ad("rsync $crldp $fn");
            my $ft_pem = File::Temp->new();
            my $fn_pem = $ft_pem->filename();
            system_ad("$openssl crl -inform DER -in $fn -outform PEM -out $fn_pem > /dev/null 2>&1");
            my @lines = read_file("$fn_pem");
            my $new_crl = join "", @lines;
            push @extra_crls, $new_crl;
        }
    }

    # In principle, it should be possible to pass all the certificates
    # got via AIA pointers to -certfile, and the TA to -CAfile, and
    # have verify use the CAs from -certfile but only validate if
    # there's a path to the TA.  In practice, -certfile appears not to
    # be referred to for CA certificates in this way.  To work around
    # this, if certificates are going to be passed in via -certfile,
    # then confirm that one of them has a SKI matching one of the TA's
    # SKIs (the AIAs should terminate at the TA).

    if (@extra_certs) {
        my %ta_skis =
            map { $self->{'openssl'}->get_ski($_) => 1 }
                @{$ta};
        my %cert_skis =
            map { $self->{'openssl'}->get_ski($_) => 1 }
                @extra_certs;
        my $has_ta = 0;
        for my $ta_ski (keys %ta_skis) {
            if ($cert_skis{$ta_ski}) {
                $has_ta = 1;
                last;
            }
        }
        if (not $has_ta) {
            die "No provided TA found in certificates got via AIAs.\n";
        }
    }

    my $ft_certfile = File::Temp->new();
    if (@extra_certs) {
        for my $entry (@extra_certs) {
            chomp $entry;
            print $ft_certfile $entry;
            print $ft_certfile "\n";
        }
    } else {
        for my $entry (@{$ta}) {
            chomp $entry;
            print $ft_certfile $entry;
            print $ft_certfile "\n";
        }
    }
    $ft_certfile->flush();
    my $fn_certfile = $ft_certfile->filename();

    my $ft_crlfile = File::Temp->new();
    for my $entry (@extra_crls) {
        chomp $entry;
        print $ft_crlfile $entry;
        print $ft_crlfile "\n";
    }
    $ft_crlfile->flush();
    my $fn_crlfile = $ft_crlfile->filename();

    my $ft_output = File::Temp->new();
    my $fn_output = $ft_output->filename();
    my $ft_error = File::Temp->new();
    my $fn_error = $ft_error->filename();

    eval { system_ad("$openssl cms -verify -inform DER ".
              "-in $fn ".
              "-CAfile $fn_certfile ".
              (@extra_crls ? " -crl_check_all -CRLfile $fn_crlfile " : '').
              "-out $fn_output 2>&1",
              0); };
    if (my $error = $@) {
        eval { system_ad("$openssl cms -verify -inform DER ".
              "-in $fn ".
              "-CAfile $fn_certfile ".
              (@extra_crls ? " -crl_check_all -CRLfile $fn_crlfile " : '').
              "-out $fn_output 2> $fn_error",
              1); };
        my $data = read_file($fn_error);
        $data =~ s/\n/ /g;
        die $data."\n";
    }

    my $aspa_data = read_file($fn_output);
    my $aspa = APNIC::RPKI::ASPA->new();
    $aspa->decode($aspa_data);

    my $version = $aspa->version();
    if ($version != 0) {
        die "ASPA version is invalid: expected '0', got '$version'";
    }

    my $customer_asn = $aspa->customer_asn();
    if ($as_set->intersect($customer_asn)->empty()) {
        die "ASPA ASN is not present in certificate";
    }

    my @providers = @{$aspa->providers()};
    my %seen;
    my $last;
    for my $provider (@providers) {
        my $asn = $provider->{'provider_asn'};
        if ($seen{$asn}) {
            die "ASPA contains duplicate provider ASN";
        }
        $seen{$asn} = 1;
        if (defined $last) {
            if ($last > $asn) {
                die "ASPA providers are not in order";
            }
        }
        if (exists $provider->{'afi_limit'}) {
            my $afi_limit = $provider->{'afi_limit'};
            if (not ($afi_limit == 1 or $afi_limit == 2)) {
                die "ASPA provider AFI limit is invalid";
            }
        }
        $last = $asn;
    }

    return 1;
}

1;
