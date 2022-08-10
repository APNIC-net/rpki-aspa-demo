package APNIC::RPKI::CA;

use warnings;
use strict;

use DateTime;
use File::Slurp qw(read_file
                   write_file);
use File::Temp qw(tempdir);
use HTTP::Daemon;
use HTTP::Status qw(:constants);
use MIME::Base64;
use Net::IP;
use LWP::UserAgent;
use Storable;
use XML::LibXML;
use YAML;
use MIME::Base64 qw(encode_base64url);

use APNIC::RPKI::Manifest;
use APNIC::RPKI::OpenSSL;
use APNIC::RPKI::Utils qw(system_ad);

use constant CA_CONFIG_PARAMETERS => qw(dir ca root_ca_ext_extra
                                        signing_ca_ext_extra);

use constant CA_CONFIG => <<EOF;
[ default ]
ca                      = root-ca
dir                     = .

[ req ]
default_bits            = 2048
encrypt_key             = yes
default_md              = sha256
utf8                    = no
string_mask             = pkix
prompt                  = no
distinguished_name      = ca_dn
req_extensions          = ca_reqext

[ ca_dn ]
commonName              = "root"

[ ca_reqext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true
subjectKeyIdentifier    = hash

[ pqs ]
policyIdentifier        = 1.3.6.1.5.5.7.14.2

[ ca ]
default_ca              = root_ca

[ root_ca ]
certificate             = {dir}/ca/{ca}.crt
private_key             = {dir}/ca/{ca}/private/{ca}.key
new_certs_dir           = {dir}/ca/{ca}
serial                  = {dir}/ca/{ca}/db/{ca}.crt.srl
crlnumber               = {dir}/ca/{ca}/db/{ca}.crl.srl
database                = {dir}/ca/{ca}/db/{ca}.db
unique_subject          = no
default_days            = 3652
default_md              = sha256
policy                  = match_pol
email_in_dn             = no
preserve                = no
name_opt                = ca_default
cert_opt                = ca_default
copy_extensions         = none
x509_extensions         = signing_ca_ext
default_crl_days        = 365
crl_extensions          = crl_ext

[ match_pol ]
commonName              = supplied

[ any_pol ]
domainComponent         = optional
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = optional
emailAddress            = optional

[ root_ca_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always
certificatePolicies     = critical,\@pqs
{root_ca_ext_extra}

[ signing_ca_ext ]
keyUsage                = critical,digitalSignature
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always
certificatePolicies     = critical,\@pqs
{signing_ca_ext_extra}

[ crl_ext ]
authorityKeyIdentifier  = keyid:always
EOF

use constant EE_CSR_FILENAME  => 'ee.csr';
use constant EE_CERT_FILENAME => 'ee.crt';
use constant EE_KEY_FILENAME  => 'ee.key';
use constant CRL_FILENAME     => 'crl.pem';

use constant ID_CT_ASPA => '1.2.840.113549.1.9.16.1.49';
use constant ID_CT_MFT  => '1.2.840.113549.1.9.16.1.26';

use constant ID_SIA_REPO         => '1.3.6.1.5.5.7.48.5';
use constant ID_SIA_MANIFEST     => '1.3.6.1.5.5.7.48.10';
use constant ID_SIA_SIGNEDOBJECT => '1.3.6.1.5.5.7.48.11';

our $DEBUG = 0;

our $VERSION = '0.1';

sub new
{
    my $class = shift;

    my %args = @_;
    my $self = \%args;
    bless $self, $class;

    if (not $self->{'ca_path'}) {
        die "'ca_path' argument must be provided.";
    }
    if (not $self->{'openssl'}) {
        $self->{'openssl'} = APNIC::RPKI::OpenSSL->new();
    }

    return $self;
}

sub _chdir_ca
{
    my ($self) = @_;

    chdir $self->{'ca_path'} or die "$! (".$self->{'ca_path'}.")";

    return 1;
}

sub _system
{
    my (@args) = @_;

    my $cmd = join " ", @args;

    return system_ad($cmd, $DEBUG);
}

sub is_initialised
{
    my ($self) = @_;

    $self->_chdir_ca();

    return (-e "ca.cnf");
}

sub _generate_config
{
    my ($self, %parameters) = @_;

    my $config = CA_CONFIG();
    my $ca_path = $self->{'ca_path'};
    $config =~ s/{dir}/$ca_path/g;
    $config =~ s/{ca}/ca/g;

    for my $key (keys %parameters) {
        my $value = $parameters{$key};
        $config =~ s/{$key}/$value/g;
    }

    for my $key (CA_CONFIG_PARAMETERS()) {
        $config =~ s/{$key}//g;
    }

    write_file('ca.cnf', $config);

    return 1;
}

sub initialise
{
    my ($self, $common_name, $key_only, $stg_repo_dir, $repo_dir,
        $host, $port) = @_;

    if (not defined $port) {
        $port = 873;
    }
    if (not $host or not $port or not $stg_repo_dir or not $repo_dir) {
        die "Expected extra arguments";
    }
    my $port_str = ($port == 873) ? "" : ":$port";
    my $host_and_port = $host.$port_str;

    $self->_chdir_ca();

    if ($self->is_initialised()) {
        die "CA has already been initialised.";
    }

    $self->_generate_config();

    for my $dir (qw(newcerts ca ca/ca ca/ca/private ca/ca/db)) {
        mkdir $dir or die $!;
    }
    for my $file (qw(ca/ca/db/ca.db ca/ca/db/ca.db.attr index.txt)) {
        _system("touch $file");
    }
    for my $serial_file (qw(ca.crt.srl ca.crl.srl)) {
        write_file("ca/ca/db/$serial_file", "01");
    }

    my $path = $self->{'ca_path'};
    my ($name) = ($path =~ /.*\/(.*)\/?/);

    my $openssl = $self->{'openssl'}->get_openssl_path();
    _system("$openssl genrsa -out ca/ca/private/ca.key 2048");
    my $key_data = read_file("ca/ca/private/ca.key");
    my $gski = $self->{'openssl'}->get_key_ski($key_data);

    my $stg_repo = $stg_repo_dir.'/'.$name;
    mkdir $stg_repo or die $!;
    my $repo = $repo_dir.'/'.$name;
    mkdir $repo or die $!;

    my $aia = undef;
    my $sia = ID_SIA_REPO().";URI:rsync://$host_and_port/repo/$name/";
    my $mft_sia = ID_SIA_MANIFEST().";URI:rsync://$host_and_port/repo/$name/$gski.mft";

    if (not $key_only) {
        my $extra = $self->_generate_sbgp_config(['0.0.0.0/0'], ['1-65536']);
        $extra = "subjectInfoAccess=$sia,$mft_sia\n$extra";
        $self->_generate_config(root_ca_ext_extra => $extra);

        _system("$openssl req -new -config ca.cnf -extensions root_ca_ext ".
                "-x509 -key ca/ca/private/ca.key -out ca/ca.crt -subj '/CN=$common_name'");
        _system("$openssl x509 -in ca/ca.crt -outform DER -out ca/ca.der.cer");
        _system("cp ca/ca.der.cer $repo_dir/$gski.cer");
        
        my $ft = File::Temp->new();
        my $fn = $ft->filename();
        my @key_data = `$openssl x509 -in ca/ca.crt -noout -pubkey`;
        shift @key_data;
        pop @key_data;

        $aia = "rsync://$host_and_port/repo/$gski.cer";
        write_file("$repo_dir/$gski.tal", <<EOF);
$aia

@key_data
EOF
    }

    my $own_config = {
        name            => $name,
        host            => $host,
        port            => $port,
        host_and_port   => $host_and_port,
        stg_repo        => $stg_repo,
        repo            => $repo,
        self_signed     => (not $key_only),
        aia             => $aia,
        gski            => $gski,
        sia             => $sia,
        mft_sia         => $mft_sia,
        manifest_number => 0,
    };
    YAML::DumpFile('config.yml', $own_config);

    return 1;
}

sub get_config
{
    my ($self) = @_;

    $self->_chdir_ca();
    return YAML::LoadFile('config.yml');
}

sub get_cert_rsync_url
{
    my ($self) = @_;

    my $own_config = YAML::LoadFile('config.yml');
    return $own_config->{'aia'};
}

sub get_ca_request
{
    my ($self, $common_name, $ip_resources, $as_resources) = @_;

    $self->_chdir_ca();

    my $openssl = $self->{'openssl'}->get_openssl_path();
    _system("$openssl req -new -key ca/ca/private/ca.key ".
            "-out ca/ca.req -subj '/CN=$common_name'");

    my $data = read_file('ca/ca.req');
    return $data;
}

sub _generate_sbgp_config
{
    my ($self, $ip_resources, $as_resources) = @_;

    my $ipv4_index = 0;
    my $ipv6_index = 0;

    my @ip_lines;
    if ((ref $ip_resources) eq 'ARRAY') {
        for my $ip_resource (@{$ip_resources}) {
            my $type = Net::IP->new($ip_resource)->version();
            if ($type == 4) {
                push @ip_lines, "IPv4.$ipv4_index = $ip_resource";
                $ipv4_index++;
            } else {
                push @ip_lines, "IPv6.$ipv6_index = $ip_resource";
                $ipv6_index++;
            }
        }
    } elsif (not defined $ip_resources) {
        @ip_lines = (
            'IPv4 = inherit',
            'IPv6 = inherit'
        );
    }

    my $ip_content =
        (@ip_lines)
            ? "[ ip-section ]\n".(join "\n", @ip_lines)."\n\n"
            : "";

    my $as_index = 0;
    my @as_lines;
    if ((ref $as_resources) eq 'ARRAY') {
        for my $as_resource (@{$as_resources}) {
            push @as_lines, "AS.$as_index = $as_resource";
            $as_index++;
        }
    } elsif (not defined $as_resources) {
        @as_lines = (
            'AS = inherit'
        );
    }

    my $as_content =
        (@as_lines)
            ? "[ as-section ]\n".(join "\n", @as_lines)."\n\n"
            : "";

    my @preliminary = (
        ((@ip_lines)
            ? 'sbgp-ipAddrBlock = critical, @ip-section'
            : ''),
        ((@as_lines)
            ? 'sbgp-autonomousSysNum = critical, @as-section'
            : '')
    );

    my $result =
        join "\n",
            ((@preliminary), "\n", $ip_content, $as_content);
    return $result;
}

sub mod_gutmannize
{
    my $data = shift
        or return;

    $data or return '';

    my $base64url_data = encode_base64url($data);
    my $output         = $base64url_data;
    chomp $output;
    $output =~ s/=$//;

    return $output;
}

sub sign_ca_request
{
    my ($self, $request, $ip_resources, $as_resources) = @_;

    $self->_chdir_ca();

    my $ft_request = File::Temp->new();
    print $ft_request $request;
    $ft_request->flush();
    my $fn_request = $ft_request->filename();

    $ip_resources ||= [];
    $as_resources ||= [];

    my $extra = $self->_generate_sbgp_config($ip_resources, $as_resources);
    my $openssl = $self->{'openssl'}->get_openssl_path();

    my @req_pubkey = `$openssl req -in $fn_request -pubkey -noout`;
    chomp for @req_pubkey;
    my $req_pubkey_str = join '', @req_pubkey;
    my @ca_pubkey = `$openssl x509 -in ca/ca.crt -pubkey -noout`;
    chomp for @ca_pubkey;
    my $ca_pubkey_str = join '', @ca_pubkey;

    my $own_config = YAML::LoadFile('config.yml');
    my $aia = $own_config->{'aia'};
    my $gski = $own_config->{'gski'};
    my $host_and_port = $own_config->{'host_and_port'};

    my $path = $self->{'ca_path'};
    my ($name) = ($path =~ /.*\/(.*)\/?/);

    if ($req_pubkey_str ne $ca_pubkey_str) {
        $extra = 'authorityInfoAccess=caIssuers;URI:'.
                 "$aia\n".
                 'crlDistributionPoints=URI:'.
                 "rsync://$host_and_port/repo/$name/$gski.crl\n".
                 'subjectInfoAccess='.$own_config->{'sia'}.','.
                                      $own_config->{'mft_sia'}."\n".
                  $extra;
    }

    $self->_generate_config(root_ca_ext_extra => $extra);

    my $ft_output = File::Temp->new();
    my $fn_output = $ft_output->filename();

    _system("$openssl ca -batch -config ca.cnf -extensions root_ca_ext ".
            "-out $fn_output ".
            "-in $fn_request -days 365");

    my $data = read_file($fn_output);
    my $ski = $self->{'openssl'}->get_ski($data);
    my $bin_ski = pack('H*', $ski);
    my $cert_gski = mod_gutmannize($bin_ski);

    return ($data, "rsync://$host_and_port/repo/$name/$cert_gski.cer");
}

sub install_ca_certificate
{
    my ($self, $certificate, $aia) = @_;

    $self->_chdir_ca();

    my $ft_cert = File::Temp->new();
    print $ft_cert $certificate;
    $ft_cert->flush();
    my $fn_cert = $ft_cert->filename();

    my $openssl = $self->{'openssl'}->get_openssl_path();
    _system("$openssl x509 -in $fn_cert -out ca/ca.crt");
    _system("$openssl x509 -in ca/ca.crt -outform DER -out ca/ca.der.cer");

    my ($gski) = ($aia =~ /.*\/(.*).cer/);
    my $own_config = YAML::LoadFile('config.yml');
    $own_config->{'aia'} = $aia;
    $own_config->{'gski'} = $gski;
    my $host_and_port = $own_config->{'host_and_port'};

    my $path = $self->{'ca_path'};
    my ($name) = ($path =~ /.*\/(.*)\/?/);

    $own_config->{'mft_sia'} =
        ID_SIA_MANIFEST().";URI:rsync://$host_and_port/repo/$name/$gski.mft";

    YAML::DumpFile('config.yml', $own_config);

    return 1;
}

sub revoke_current_ee_certificate
{
    my ($self) = @_;

    $self->_chdir_ca();

    if (-e "ee.crt") {
        my $openssl = $self->{'openssl'}->get_openssl_path();
        _system("$openssl ca -batch -config ca.cnf ".
                "-revoke ".EE_CERT_FILENAME());
    }

    return 1;
}

sub issue_new_ee_certificate
{
    my ($self, $ip_resources, $as_resources, @sias) = @_;

    $self->_chdir_ca();

    my $own_config = YAML::LoadFile('config.yml');
    my $aia = $own_config->{'aia'};
    my $gski = $own_config->{'gski'};
    my $host_and_port = $own_config->{'host_and_port'};

    my $extra = $self->_generate_sbgp_config($ip_resources, $as_resources);
    my $path = $self->{'ca_path'};
    my ($name) = ($path =~ /.*\/(.*)\/?/);
    $extra = 'authorityInfoAccess=caIssuers;URI:'.
             "$aia\n".
             'crlDistributionPoints=URI:'.
             "rsync://$host_and_port/repo/$name/$gski.crl\n".
             'subjectInfoAccess='.(join ',', @sias)."\n".
             $extra;

    $self->_generate_config(signing_ca_ext_extra => $extra);

    my $openssl = $self->{'openssl'}->get_openssl_path();
    _system("$openssl genrsa ".
            "-out ".EE_KEY_FILENAME()." 2048");
    _system("$openssl req -new ".
            "-config ca.cnf -extensions root_ca_ext ".
            "-key ".EE_KEY_FILENAME()." ".
            "-out ".EE_CSR_FILENAME()." ".
            "-subj '/CN=EE'");
    _system("$openssl ca -batch -config ca.cnf ".
            "-out ".EE_CERT_FILENAME()." ".
            "-extensions signing_ca_ext ".
            "-in ".EE_CSR_FILENAME()." -days 365");

    my $data = read_file(EE_CERT_FILENAME());

    return $data;
}

sub issue_crl
{
    my ($self) = @_;

    $self->_chdir_ca();

    my $openssl = $self->{'openssl'}->get_openssl_path();
    _system("$openssl ca -batch -crlexts crl_ext -config ca.cnf -gencrl ".
            "-out ".CRL_FILENAME());
    _system("$openssl crl -in ".CRL_FILENAME()." -outform DER -out ".
            "crl.der.crl");

    my $own_config = YAML::LoadFile('config.yml');
    my $aia = $own_config->{'aia'};
    my $gski = $own_config->{'gski'};
    my $stg_repo = $own_config->{'stg_repo'};

    system("cp crl.der.crl $stg_repo/$gski.crl");

    return 1;
}

sub get_crl
{
    my ($self) = @_;

    $self->_chdir_ca();

    my $data = read_file(CRL_FILENAME());
    return $data;
}

sub get_ee
{
    my ($self) = @_;

    $self->_chdir_ca();

    my $data = read_file(EE_CERT_FILENAME());
    return $data;
}

sub issue_aspa
{
    my ($self, $aspa, $url) = @_;

    my $sia = ID_SIA_SIGNEDOBJECT().";URI:$url";
    my $customer_asn = $aspa->customer_asn();
    $self->issue_new_ee_certificate([], [$customer_asn], $sia);

    system("cp ".EE_CERT_FILENAME()." /tmp/ee");

    return $self->sign_cms($aspa->encode(), ID_CT_ASPA());
}

sub issue_manifest
{
    my ($self) = @_;

    my $own_config = YAML::LoadFile('config.yml');
    my $sia = $own_config->{'mft_sia'};
    $sia =~ s/\.10;/.11;/;
    $self->issue_new_ee_certificate(undef, undef, $sia);
    my $aia = $own_config->{'aia'};
    my $gski = $own_config->{'gski'};

    $own_config->{'manifest_number'}++;
    my $manifest_number = $own_config->{'manifest_number'};
    my $this_update = DateTime->now(time_zone => 'UTC');
    my $next_update = DateTime->now(time_zone => 'UTC')->add(days => 2);
    my $stg_repo = $own_config->{'stg_repo'};
    my @files = `ls $stg_repo`;
    chomp for @files;
    my @mft_files;
    for my $file (@files) {
        my ($ss) = `sha256sum $stg_repo/$file`;
        chomp $ss;
        $ss =~ s/ .*//;
        push @mft_files, {
            filename => $file,
            hash => pack('H*', $ss)
        };
    }

    my $mft = APNIC::RPKI::Manifest->new();
    $mft->manifest_number($manifest_number);
    $mft->this_update($this_update);
    $mft->next_update($next_update);
    $mft->files(\@mft_files);

    my $mft_proper = $self->sign_cms($mft->encode(), ID_CT_MFT());
    write_file("$stg_repo/$gski.mft", $mft_proper);

    return 1;
}

sub publish_file
{
    my ($self, $filename, $data) = @_;

    my $own_config = YAML::LoadFile('config.yml');
    my $stg_repo = $own_config->{'stg_repo'};
    write_file("$stg_repo/$filename", $data);

    return 1;
}

sub publish
{
    my ($self) = @_;

    $self->issue_crl();
    $self->issue_manifest();

    my $own_config = YAML::LoadFile('config.yml');
    my $aia = $own_config->{'aia'};
    my $gski = $own_config->{'gski'};
    my $stg_repo = $own_config->{'stg_repo'};
    my $repo = $own_config->{'repo'};

    my $res = system("rm -f $repo/*");
    if ($res != 0) {
        die "Unable to clear current repository state";
    }
    $res = system("cp $stg_repo/* $repo/");
    if ($res != 0) {
        die "Unable to copy staging state to repository";
    }

    return 1;
}

sub sign_cms
{
    my ($self, $input, $content_type) = @_;

    $self->_chdir_ca();

    my $ft_input = File::Temp->new();
    print $ft_input $input;
    $ft_input->flush();
    my $fn_input = $ft_input->filename();

    my $ft_output= File::Temp->new();
    my $fn_output = $ft_output->filename();

    my $openssl = $self->{'openssl'}->get_openssl_path();
    my $res = _system("$openssl cms -sign -nodetach -binary -outform DER ".
                      "-nosmimecap ".
                      "-keyid -md sha256 -econtent_type $content_type ".
                      "-signer ".EE_CERT_FILENAME()." ".
                      "-inkey ".EE_KEY_FILENAME()." ".
                      "-in $fn_input -out $fn_output");

    return read_file($fn_output);
}

sub get_ca_pem
{
    my ($self) = @_;

    $self->_chdir_ca();

    my @lines = read_file('ca/ca.crt');

    pop @lines;
    shift @lines;

    my $bpki_ta = join '', @lines;
    chomp $bpki_ta;

    return $bpki_ta;
}

sub get_issuer
{
    my ($self) = @_;

    $self->_chdir_ca();

    my $openssl_path = $self->{'openssl'}->{'path'};
    my ($issuer) = `$openssl_path x509 -in ca/ca.crt -noout -issuer`;
    chomp $issuer;
    $issuer =~ s/.*=//;
    return $issuer;
}

sub get_subject
{
    my ($self) = @_;

    $self->_chdir_ca();

    my $openssl_path = $self->{'openssl'}->{'path'};
    my ($subject) = `$openssl_path x509 -in ca/ca.crt -noout -subject`;
    chomp $subject;
    $subject =~ s/.*=//;
    return $subject;
}

1;
