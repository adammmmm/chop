# CHOP
## Info
Applications ingesting pcap-files aren't always intelligent when it comes to encapsulated mirror traffic.
So it might be up to "someone" to edit the pcap-files to remove the encapsulation, leaving only the mirrored traffic as is.

Different mirror sources will create different looking pcaps.
This program is to help you get the correct editcap chop size to de-encapsulate the pcap.

## Build

```bash
go build .
```

## Run

```sh
% ./chop erspan.pcap
Found valid chop size: 58, run editcap -C 58 <inputfilename> <outputfilename>
% ./chop gre-sample.pcap
Found valid chop size: 38, run editcap -C 38 -T rawip <inputfilename> <outputfilename>
% ./chop noncapped.pcap
could not find valid chop size, most likely not encapsulated
```
