# checksum-tapestry checksum crate
![build](https://github.com/jgerrish/checksum-tapestry/actions/workflows/rust.yml/badge.svg)

This is a crate containing a selection of checksum algorithms.  It
includes CRC, Fletcher16, and Adler32,

It includes tests for all algorithms.  The tests come from various
sources.

For the CRC code, the crc-catalog crate provides a catalog of common
CRC parameters.  The parameter model this crate uses is described in:

Williams, Ross N. "A Painless Guide to CRC Error Detection
Algorithms", Rocksoft Pty Ltd., 1993, crc_ross.pdf,
http://ross.net/crc/download/crc_v3.txt

The crc crate by Rui Hu and Akhil Velagapudi also provided code
patterns that were helpful in building this library.

This document also provides a good description of what the parameters
mean.

For the Adler32 code, the Go hash package provided test cases.

Several Wikipedia pages on Computation of cyclic redundancy checks and
Adler and Fletcher checksums were also helpful.

Test cases include various values from common CRC polynomials.  This
includes the default crc32 used in zlib.


# Usage

The crate provides documentation and examples showing how to use the
different checksum algorithms.  All the checksum implementations use a
common trait called Checksum that provides two functions: compute and
update.  compute takes a u8 slice and computes a checksum over the
entire slice.  update allows rolling updates based on single u8
values.

# Security and Safety

These algorithms are not safe against side-channel attacks.

These checksum implementations have not been audited by a third-party
for use in safety critical applications.  While they provide some test
coverage, the test sources have not been checked themselves.

This crate can provide a good basis to build a test-driven checksum
library, but it should not be considered authoritative.

# References

[crc_v3.txt](http://ross.net/crc/download/crc_v3.txt "A Painless Guide to CRC Error Detection Algorithms")
Ross Williams CRC Guide is the authoritative source for a lot of
current CRC library APIs.  It describes which parameters are included
and the historical reasons they are needed.

[komrad36](https://github.com/komrad36/CRC.git "komrad36 CRC work")
The README.md file in this repository provides an easy to understand
overview of Cyclic Redundancy Checks.  It provides smaller, easier to
work through examples than some of the other tutorials and references
online.

[sarwate](https://dl.acm.org/doi/pdf/10.1145/63030.63037 "Computation of Cyclic Redundancy Checks via Table Look-Up")
Dilip Sarwate was one of the first papers to describe methods for
using table to pre-compute Cyclic Redundancy codes.

[https://datatracker.ietf.org/doc/rfc3385/](RFC-3385 "iSCSI CRC Considerations")
Provides discussion of CRC selection in the context of error models.
Outlines reasons to select CRC32C for iSCSI.
