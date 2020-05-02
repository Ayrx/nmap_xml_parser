# nmap_xml_parser

[![Crates.io](https://img.shields.io/crates/v/nmap_xml_parser?style=flat-square)](https://crates.io/crates/nmap_xml_parser)

`nmap_xml_parser` parses Nmap XML output into Rust. For example:

```rust
use nmap_xml_parser::NmapResults;
let content = fs::read_to_string(nmap_xml_file).unwrap();
let results = NmapResults::parse(&content).unwrap();
```

Please refer to the documentation for more information.
