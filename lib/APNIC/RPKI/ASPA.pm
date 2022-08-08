package APNIC::RPKI::ASPA;

use warnings;
use strict;

use Convert::ASN1;
use DateTime;

use constant ID_SMIME   => '1.2.840.113549.1.9.16';
use constant ID_CT      => ID_SMIME . '.1';
use constant ID_CT_ASPA => ID_CT . '.49';

use constant ASPA_ASN1 => q<
    ASID ::= INTEGER

    AddressFamilyIdentifier ::= OCTET STRING 

    ProviderAS ::= SEQUENCE {
	providerASID  ASID,
	afiLimit      AddressFamilyIdentifier OPTIONAL
    }

    ProviderASSet ::= SEQUENCE OF ProviderAS

    ASPAVersion ::= INTEGER

    ASProviderAttestation ::= SEQUENCE {
	version [0]   ASPAVersion OPTIONAL,
	customerASID  ASID,
	providers     ProviderASSet
    }
>;

use base qw(Class::Accessor);
APNIC::RPKI::ASPA->mk_accessors(qw(
    version
    customer_asn
    providers
));

sub new
{
    my ($class) = @_;

    my $parser = Convert::ASN1->new();
    $parser->configure(
        encoding => "DER",
        encode   => { time => "utctime" },
        decode   => { time => "utctime" },
        tagdefault => 'EXPLICIT',
    );
    my $res = $parser->prepare(ASPA_ASN1());
    if (not $res) {
        die $parser->error();
    }
    $parser = $parser->find('ASProviderAttestation');

    my $self = { parser => $parser };
    bless $self, $class;
    return $self;
}

sub decode
{
    my ($self, $aspa) = @_;

    my $parser = $self->{'parser'};
    my $data = $parser->decode($aspa);
    if (not $data) {
        die $parser->error();
    }

    my $version =
        (exists $data->{'version'} and defined $data->{'version'})
            ? $data->{'version'}
            : 0;
    $self->version(0);
    $self->customer_asn($data->{'customerASID'});

    my @providers;
    for my $provider (@{$data->{'providers'}}) {
        my $asn = $provider->{'providerASID'};
        my $afi_limit;
        if (my $al = $provider->{'afiLimit'}) {
            my @chars = split //, $al;
            $afi_limit = ord $chars[1];
        }
        push @providers, {
            provider_asn => $asn,
            (defined $afi_limit)
                ? (afi_limit => $afi_limit)
                : ()
        };
    }
    $self->providers(@providers);

    return 1;
}

sub encode
{
    my ($self) = @_;

    my $data = {};

    my $version = $self->version();
    if (not defined $version) {
        $version = 0;
    }
    $data->{'version'} = $version;

    $data->{'customerASID'} = $self->customer_asn();

    my @providers;
    for my $provider (@{$self->providers()}) {
        my $asn = $provider->{'provider_asn'};
        my $al;
        if (my $afi_limit = $provider->{'afi_limit'}) {
            $al = join '', (chr(0), chr($afi_limit));
        }
        push @providers, {
            providerASID => $asn,
            ($al ? (afiLimit => $al) : ())
        };
    }
    $data->{'providers'} = \@providers;

    my $parser = $self->{'parser'};
    my $aspa = $parser->encode($data);
    if (not $aspa) {
        die $parser->error();
    }

    return $aspa;
}

sub equals
{
    my ($self, $other) = @_;

    if ($self->version() != $other->version()) {
        return;
    }
    if ($self->customer_asn() != $other->customer_asn()) {
        return;
    }
    my @p1 =
        sort { $a->{'provider_asn'} <=> $b->{'provider_asn'} }
            @{$self->{'providers'}};
    my @p2 =
        sort { $a->{'provider_asn'} <=> $b->{'provider_asn'} }
            @{$other->{'providers'}};
    if (@p1 != @p2) {
        return;
    }
    for (my $i = 0; $i < @p1; $i++) {
        my $pp1 = $p1[$i];
        my $pp2 = $p2[$i];
        if ($pp1->{'provider_asn'} != $pp2->{'provider_asn'}) {
            return;
        }
        if ($pp1->{'afi_limit'}) {
            if ($pp1->{'afi_limit'} != $pp2->{'afi_limit'}) {
                return;
            }
        }
    }
    return 1;
}

1;
