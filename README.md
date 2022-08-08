## rpki-aspa-demo

A proof-of-concept for constructing and validating RPKI Autonomous
System Provider Authorization (ASPA) objects.
See [https://www.ietf.org/archive/id/draft-ietf-sidrops-aspa-profile-09.txt](https://www.ietf.org/archive/id/draft-ietf-sidrops-aspa-profile-09.txt).

### Build

    $ docker build -t apnic/rpki-aspa .

### Usage

    $ docker run -it apnic/rpki-aspa /bin/bash

#### Basic ASPA

    # /sbin/service rsync start
    # setup-ca --name ca --resources 1234
    # issue-aspa --ca-name ca --customer-asn 1234 --provider-asn 1235 --out my.asa
    # verify-aspa --in my.asa
    Verification succeeded.

### Todo

   - More CMS validity checks.
   - Documentation/tidying of code.

### License

See [LICENSE](./LICENSE).
