//!Parse Nmap XML output into Rust.
//!
//!The root of this crate is
//![`NmapResults::parse()`](struct.NmapResults.html#method.parse). Its use
//!should be similar to the following:
//!
//!```
//!# use std::path::PathBuf;
//!# use std::fs;
//!use nmap_xml_parser::NmapResults;
//!# let mut nmap_xml_file = PathBuf::new();
//!# nmap_xml_file.push(&std::env::var("CARGO_MANIFEST_DIR").unwrap());
//!# nmap_xml_file.push("tests/test.xml");
//!let content = fs::read_to_string(nmap_xml_file).unwrap();
//!let results = NmapResults::parse(&content).unwrap();
//!```
//!
//!This crate is still a work-in-progress and does not represent the full
//!Nmap output structure. However, it _should_ successfully parse any Nmap XML
//!output. Please file a bug report if it fails.
//!
//!The API is __not stable__ and is subject to breaking changes until the
//!crate reaches 1.0. Use with care.
pub use crate::host::HostDetails;
pub use crate::port::Port;
use std::sync::Arc;

use roxmltree::{Document, Node};

pub mod host;
pub mod port;

pub use crate::host::Host;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("error parsing file as XML document")]
    XmlError(#[from] roxmltree::Error),
    #[error("error parsing Nmap XML output: {0}")]
    InvalidNmapOutput(String),
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Self::InvalidNmapOutput(s.to_string())
    }
}

///Root structure of a Nmap scan result.
#[derive(Clone, Debug)]
pub struct NmapResults {
    ///List of hosts in the Nmap scan.
    pub hosts: Vec<Host>,

    ///Start time of the Nmap scan as seconds since Unix epoch.
    pub scan_start_time: i64,

    ///End time of the Nmap scan as seconds since Unix epoch.
    pub scan_end_time: i64,
}

impl NmapResults {
    pub fn parse(xml: &str) -> Result<Self, Error> {
        let doc = Document::parse(&xml)?;
        let root_element = doc.root_element();
        if root_element.tag_name().name() != "nmaprun" {
            return Err(Error::from("expected `nmaprun` root tag"));
        }

        let scan_start_time = root_element
            .attribute("start")
            .ok_or_else(|| Error::from("expected start time attribute"))
            .and_then(|s| {
                s.parse::<i64>()
                    .or_else(|_| Err(Error::from("failed to parse start time")))
            })?;

        let mut hosts: Vec<Host> = Vec::new();
        let mut scan_end_time = None;

        for child in root_element.children() {
            match child.tag_name().name() {
                "host" => {
                    hosts.push(Host::parse(child)?);
                }
                "runstats" => scan_end_time = Some(parse_runstats(child)?),
                _ => {}
            }
        }

        let scan_end_time =
            scan_end_time.ok_or_else(|| Error::from("expected scan_end_time in runstats"))?;

        Ok(NmapResults {
            hosts,
            scan_start_time,
            scan_end_time,
        })
    }

    /// Returns an iterator over the hosts present in the Nmap Scan
    pub fn hosts(&self) -> std::slice::Iter <Host>{
        self.hosts.iter()
    }
}

impl IntoIterator for NmapResults {
    type Item = (Arc<HostDetails>, Port);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let mut results: Vec<Self::Item> = Vec::new();

        // map each host onto an iterator over (host, port) keeping the host
        // part static, then flatten to make a single iterator

        for host in &self.hosts {
            for port in host.port_info.iter() {
                results.push((host.host_details.clone(), port.clone()));
            }
        }
        results.into_iter()
    }
}

fn parse_runstats(node: Node) -> Result<i64, Error> {
    for child in node.children() {
        if child.tag_name().name() == "finished" {
            let finished = child
                .attribute("time")
                .ok_or_else(|| Error::from("expected `time` `runstats`.`finished`"))
                .and_then(|s| {
                    s.parse::<i64>()
                        .or_else(|_| Err(Error::from("failed to parse end time")))
                })?;
            return Ok(finished);
        }
    }

    Err(Error::from("expected `finished` tag in `runstats`"))
}
