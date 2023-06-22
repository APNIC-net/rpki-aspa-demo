## rpki-aspa-demo

A proof-of-concept for constructing and validating RPKI Autonomous
System Provider Authorization (ASPA) objects.
See [https://www.ietf.org/archive/id/draft-ietf-sidrops-aspa-profile-15.txt](https://www.ietf.org/archive/id/draft-ietf-sidrops-aspa-profile-15.txt).

### Build

    $ docker build -t apnic/rpki-aspa .

### Usage

    $ docker run -it apnic/rpki-aspa /bin/bash

#### Basic ASPA

    # /sbin/service rsync start
    # setup-ca --name ta --resources 1234
    # sign-aspa --ca-name ta --customer-asn 1234 --provider-asn 1235 --out my.asa
    # verify-aspa --ca-name ta --in my.asa
    Verification succeeded.

#### Multiple CAs

    # /sbin/service rsync start
    # setup-ca --name ta --resources 1-65000
    # setup-ca --name ca --parent-name ta --resources 1234
    # sign-aspa --ca-name ca --customer-asn 1234 --provider-asn 1235 --out my.asa
    # verify-aspa --ca-name ta --in my.asa
    Verification succeeded.

#### Incorrect customer ASN

    # /sbin/service rsync start
    # setup-ca --name ta --resources 1234
    # sign-aspa --ca-name ta --customer-asn 1236 --provider-asn 1235 --out my.asa
    # verify-aspa --ca-name ta --in my.asa
    Verification failed: ... RFC 3779 resource not subset of parent's resources

### Todo

   - Documentation/tidying of code.

### License

See [LICENSE](./LICENSE).
