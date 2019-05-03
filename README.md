# tpec: 2P-ECDSA Signatures

This package contains:
 - An implementation of [Fast Secure Two-Party ECDSA Signing](https://eprint.iacr.org/2017/552.pdf), supporting key generation and two-party signing.
 - An implementation of 2P-ECDSA Adaptor Signatures detailed in [Multi-Hop Locks for Secure, Privacy-Preserving and Interoperable Payment-Channel Networks](https://eprint.iacr.org/2018/472.pdf).
   - [x] Single Hop
   - [ ] Multi-Hop (coming soon)
   

Prerequisites
=============
`go1.11` or higher
   
Installation
============
```
GO111MODULE=on go install github.com/cfromknecht/tpec
```

Running Demo
============
2P-ECDSA signature for a given message:
```
tpec -message="hello 2p-ecdsa"
```

2P-ECDSA signature for a message digest:
```
tpec -digest=f25b10e68539ba917b2ae2028326ee5ce46c386746b15ae5585813b08f5aceae
```

To reveal a secret from party 2 to party1, use the `-secret` flag:
```
tpec -message="who are you" -secret=20a5beef
```

For help, run `tpec -h`.

Warning
=======
THIS IS A PROOF OF CONCEPT IMPLEMENTATION BEING USED FOR RESEARCH. USE AT YOUR OWN RISK.

Benchmarks
==========
```
go test -v -bench=. -benchtime=30s
```

|                         | Latency | Memory | Allocations |
|-------------------------|---------|--------|-------------|
| BenchmarkKeyGen         | 599ms   | 6.46MB | 12176       |
| BenchmarkSign           | 17.8ms  | 122KB  | 717         |
| BenchmarkScriptlessSign | 18.8ms  | 142KB  | 1074        |


Results computed on 2.8 GHz Intel Core i7 16 GB 2133 MHz LPDDR3
