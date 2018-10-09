# tpec: 2P-ECDSA Signatures

This package contains:
 - An implementation of [Fast Secure Two-Party ECDSA Signing](https://eprint.iacr.org/2017/552.pdf), supporting key generation and two-party signing.
 - An implementation of 2P-ECDSA Adaptor Signatures detailed in [Multi-Hop Locks for Secure, Privacy-Preserving and Interoperable Payment-Channel Networks](https://eprint.iacr.org/2018/472.pdf).
   - [x] Single Hop
   - [ ] Multi-Hop (coming soon)
   
   
Prerequesites
=============
```
go get -u github.com/golang/dep/cmd/dep
```

Installation
============
```
go get -d github.com/cfromknecht/tpec
cd $GOPATH/src/github.com/cfromknecht/tpec
dep ensure -v
```

Running Demo
============
```
go install github.com/cfromknecht/tpec/cmd/tpec
tpec -message="hello 2p-ecdsa"
```

For help, run `tpec -h`.

Warning
=======
THIS IS A PROOF OF CONCEPT IMPLEMENTATION BEING USED FOR RESEARCH. USE AT YOUR OWN RISK.

Benchmarks
==========
```
go test -v -bench=. -benchtime=10s
```

|                         | Latency | Memory | Allocations |
|-------------------------|---------|--------|-------------|
| BenchmarkKeyGen         | 980ms   | 5.33MB | 14309       |
| BenchmarkSign           | 28.5ms  | 94.7KB | 740         |
| BenchmarkScriptlessSign | 29.9    | 115KB  | 1112        |

Results computed on 2.8 GHz Intel Core i7 16 GB 2133 MHz LPDDR3
