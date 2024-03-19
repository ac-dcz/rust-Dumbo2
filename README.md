# Dumbo2

about Dumbo2...

## Quick Start

Dumbo2 is written in Rust, but all benchmarking scripts are written in Python and run with [Fabric](http://www.fabfile.org/).
To deploy and benchmark a testbed of 4 nodes on your local machine, clone the repo and install the python dependencies:

```
$ git clone https://github.com/ac-dcz/Dumbo2
$ cd Dumbo2/benchmark
$ pip install -r requirements.txt
```

You also need to install Clang (required by rocksdb) and [tmux](https://linuxize.com/post/getting-started-with-tmux/#installing-tmux) (which runs all nodes and clients in the background). Finally, run a local benchmark using fabric:

```
$ fab local
```

This command may take a long time the first time you run it (compiling rust code in `release` mode may be slow) and you can customize a number of benchmark parameters in `fabfile.py`. When the benchmark terminates, it displays a summary of the execution similarly to the one below.

```
-----------------------------------------
 SUMMARY:
-----------------------------------------
 + CONFIG:
 Protocol: 0 
 DDOS attack: False 
 Committee size: 4 nodes
 Input rate: 10,000 tx/s
 Transaction size: 512 B
 Faults: 0 nodes
 Execution time: 32 s

 Consensus timeout delay: 2,000 ms
 Consensus sync retry delay: 10,000 ms
 Consensus max payloads size: 500 B
 Consensus min block delay: 0 ms
 Mempool queue capacity: 10,000 B
 Mempool max payloads size: 15,000 B
 Mempool min block delay: 0 ms

 + RESULTS:
 Consensus TPS: 10,036 tx/s
 Consensus BPS: 5,138,628 B/s
 Consensus latency: 142 ms

 End-to-end TPS: 9,985 tx/s
 End-to-end BPS: 5,112,331 B/s
 End-to-end latency: 188 ms
-----------------------------------------
```
