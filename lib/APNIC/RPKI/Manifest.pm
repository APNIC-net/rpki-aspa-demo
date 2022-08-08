package APNIC::RPKI::Manifest;

use warnings;
use strict;

use Convert::ASN1;
use Digest::SHA qw(sha256);
use DateTime;

use constant ID_SMIME           => '1.2.840.113549.1.9.16';
use constant ID_CT              => ID_SMIME . '.1';
use constant ID_CT_RPKIMANIFEST => ID_CT . '.26';

use constant ID_SHA256 => '2.16.840.1.101.3.4.2.1';

use constant MANIFEST_VERSION_DEFAULT => 0;

use constant MANIFEST_ASN1 => q(
  Manifest ::= SEQUENCE {
    version     [0] INTEGER OPTIONAL, -- DEFAULT 0,
    manifestNumber  INTEGER,
    thisUpdate      GeneralizedTime,
    nextUpdate      GeneralizedTime,
    fileHashAlg     OBJECT IDENTIFIER,
    fileList        SEQUENCE OF FileAndHash
  }

  FileAndHash ::=     SEQUENCE {
    file            IA5String,
    hash            BIT STRING
  }
);

use base qw(Class::Accessor);
APNIC::RPKI::Manifest->mk_accessors(qw(
    version
    manifest_number
    this_update
    next_update
    files
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
    my $res = $parser->prepare(MANIFEST_ASN1());
    if (not $res) {
        die $parser->error();
    }
    $parser = $parser->find('Manifest');

    my $self = { parser => $parser };
    bless $self, $class;
    return $self;
}

sub decode
{
    my ($self, $mft) = @_;

    my $parser = $self->{'parser'};
    my $data = $parser->decode($mft);
    if (not $data) {
        die $parser->error();
    }

    $self->manifest_number($data->{'manifestNumber'});
    $self->this_update(DateTime->from_epoch(epoch => $data->{'thisUpdate'}));
    $self->next_update(DateTime->from_epoch(epoch => $data->{'nextUpdate'}));

    if ($data->{'fileHashAlg'} ne ID_SHA256()) {
        die "unexpected hashing algorithm in manifest: ".
            $data->{'fileHashAlg'};
    }

    my @files;
    for my $file (@{$data->{'fileList'}}) {
        if ($file->{'hash'}->[1] != 256) {
            die "unexpected hash value: ".
                $file->{'hash'}->[1];
        }
        push @files, {
            filename => $file->{'file'},
            hash     => $file->{'hash'}->[0]
        };
    }
    $self->files(@files);

    return 1;
}

sub encode
{
    my ($self) = @_;

    my $parser = $self->{'parser'};

    my $data = {};

    $data->{'manifestNumber'} = $self->manifest_number();
    $data->{'thisUpdate'} = $self->this_update()->epoch();
    $data->{'nextUpdate'} = $self->next_update()->epoch();
    $data->{'fileHashAlg'} = ID_SHA256();
    $data->{'fileList'} = [ map {
        +{ file => $_->{'filename'},
           hash => [ $_->{'hash'}, 256 ] }
    } @{$self->{'files'}} ];

    my $mft = $parser->encode($data);
    if (not $mft) {
        die $parser->error();
    }

    return $mft;
}

sub equals
{
    my ($self, $other) = @_;

    if ($self->manifest_number() != $other->manifest_number()) {
        return;
    }
    if ($self->this_update()->epoch() != $other->this_update()->epoch()) {
        return;
    }
    if ($self->next_update()->epoch() != $other->next_update()->epoch()) {
        return;
    }
    my @files = @{$self->{'files'}};
    my @other_files = @{$other->{'files'}};
    if (@files != @other_files) {
        return;
    }
    for (my $i = 0; $i < @files; $i++) {
        if ($files[$i]->{'filename'} ne $other_files[$i]->{'filename'}) {
            return;
        }
        if ($files[$i]->{'hash'} ne $other_files[$i]->{'hash'}) {
            return;
        }
    }
    return 1;
}

1;
