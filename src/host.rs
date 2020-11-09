//!Host related structs and enums.
use roxmltree::Node;
use std::net::IpAddr;
use std::str::FromStr;
use strum_macros::{Display, EnumString};

use crate::port::PortInfo;
use crate::Error;

#[derive(Display, Clone, Debug, PartialEq)]
pub enum Address {
    IpAddr(IpAddr),
    MacAddr(String),
}

#[derive(Clone, Debug)]
pub struct Host {
    pub(crate) addresses: Vec<Address>,
    pub status: HostStatus,
    pub(crate) host_names: Vec<Hostname>,
    pub port_info: PortInfo,
    pub scan_start_time: Option<i64>,
    pub scan_end_time: Option<i64>,
}

impl Host {
    pub(crate) fn parse(node: Node) -> Result<Self, Error> {
        let scan_start_time = node
            .attribute("starttime")
            .map(|s| {
                s.parse::<i64>()
                    .map_err(|_| Error::from("failed to parse host start time"))
            })
            .transpose()?;

        let scan_end_time = node
            .attribute("endtime")
            .map(|s| {
                s.parse::<i64>()
                    .map_err(|_| Error::from("failed to parse host end time"))
            })
            .transpose()?;

        let mut status = None;
        let mut host_names = Vec::new();
        let mut port_info = Default::default();

        let mut addresses = Vec::new();

        for child in node.children() {
            match child.tag_name().name() {
                "address" => addresses.push(parse_address_node(child)?),
                "status" => status = Some(HostStatus::parse(child)?),
                "hostnames" => host_names = parse_hostnames_node(child)?,
                "ports" => port_info = PortInfo::parse(child)?,
                _ => {}
            }
        }

        let status = status.ok_or_else(|| Error::from("expected `status` node for host"))?;

        Ok(Host {
            scan_start_time,
            scan_end_time,
            addresses,
            status,
            host_names,
            port_info,
        })
    }

    ///Returns an iterator over the addresses associated with this host.
    pub fn addresses(&self) -> std::slice::Iter<Address> {
        self.addresses.iter()
    }

    ///Returns an iterator over the names associated with this host.
    pub fn host_names(&self) -> std::slice::Iter<Hostname> {
        self.host_names.iter()
    }
}

fn parse_address_node(node: Node) -> Result<Address, Error> {
    let addrtype = node
        .attribute("addrtype")
        .ok_or_else(|| Error::from("expected `addrtype` attribute in `address` node"))?;

    let addr = node
        .attribute("addr")
        .ok_or_else(|| Error::from("expected `addr` attribute in `address` node"))?;

    match addrtype {
        "mac" => Ok(Address::MacAddr(addr.to_string())),
        _ => {
            let a = addr
                .parse::<IpAddr>()
                .map_err(|_| Error::from("failed to parse IP address"))?;
            Ok(Address::IpAddr(a))
        }
    }
}

fn parse_hostnames_node(node: Node) -> Result<Vec<Hostname>, Error> {
    let mut r = Vec::new();

    for child in node.children() {
        if child.tag_name().name() == "hostname" {
            r.push(Hostname::parse(child)?);
        }
    }

    Ok(r)
}

#[derive(Clone, Debug)]
pub struct HostStatus {
    pub state: HostState,
    pub reason: String,
    pub reason_ttl: u8,
}

impl HostStatus {
    fn parse(node: Node) -> Result<Self, Error> {
        let s = node
            .attribute("state")
            .ok_or_else(|| Error::from("expected `state` attribute in `hoststatus` node"))?;
        let state =
            HostState::from_str(s).map_err(|_| Error::from("failed to parse host state"))?;

        let reason = node
            .attribute("reason")
            .ok_or_else(|| Error::from("expected `reason` attribute in `hoststatus` node"))?
            .to_string();

        let reason_ttl = node
            .attribute("reason_ttl")
            .ok_or_else(|| Error::from("expected `reason_ttl` attribute in `hoststatus` node"))
            .and_then(|s| {
                s.parse::<u8>()
                    .map_err(|_| Error::from("failed to parse `reason_ttl`"))
            })?;

        Ok(HostStatus {
            state,
            reason,
            reason_ttl,
        })
    }
}

#[derive(EnumString, Display, Clone, Debug, PartialEq)]
pub enum HostState {
    #[strum(serialize = "up")]
    Up,
    #[strum(serialize = "down")]
    Down,
    #[strum(serialize = "unknown")]
    Unknown,
    #[strum(serialize = "skipped")]
    Skipped,
}

#[derive(EnumString, Display, Clone, Debug, PartialEq)]
pub enum HostnameType {
    #[strum(serialize = "user", to_string = "User")]
    User,
    #[strum(serialize = "PTR", to_string = "Dns")]
    Dns,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Hostname {
    pub name: String,
    pub source: HostnameType,
}

impl Hostname {
    fn parse(node: Node) -> Result<Self, Error> {
        let name = node
            .attribute("name")
            .ok_or_else(|| Error::from("expected `name` attribute in `hostname` node"))?
            .to_string();

        let s = node
            .attribute("type")
            .ok_or_else(|| Error::from("expected `type` attribute in `hostname` node"))?;
        let source = HostnameType::from_str(s)
            .map_err(|_| Error::from("expected `source` attribute in `address` node"))?;

        Ok(Hostname { name, source })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn host_with_start_end_time() {
        let xml = r#"
<host starttime="1589292535" endtime="1589292535">
    <status state="down" reason="no-response" reason_ttl="0"/>
    <address addr="192.168.59.234" addrtype="ipv4"/>
</host>
        "#;
        let doc = Document::parse(&xml).unwrap();
        let ele = doc.root_element();
        let host = Host::parse(ele).unwrap();

        assert_eq!(host.scan_start_time, Some(1589292535));
        assert_eq!(host.scan_end_time, Some(1589292535));
    }

    #[test]
    fn host_without_start_end_time() {
        let xml = r#"
<host>
    <status state="down" reason="no-response" reason_ttl="0"/>
    <address addr="192.168.59.234" addrtype="ipv4"/>
</host>
        "#;
        let doc = Document::parse(&xml).unwrap();
        let ele = doc.root_element();
        let host = Host::parse(ele).unwrap();

        assert!(host.scan_start_time.is_none());
        assert!(host.scan_end_time.is_none());
    }

    #[test]
    fn host_with_invalid_start_time() {
        let xml = r#"
<host starttime="NOT A NUMBER" endtime="1589292535">
    <status state="down" reason="no-response" reason_ttl="0"/>
    <address addr="192.168.59.234" addrtype="ipv4"/>
</host>
        "#;
        let doc = Document::parse(&xml).unwrap();
        let ele = doc.root_element();
        let host_err = Host::parse(ele).unwrap_err();

        assert_eq!(
            host_err.to_string(),
            "error parsing Nmap XML output: failed to parse host start time"
        );
    }

    #[test]
    fn host_with_invalid_end_time() {
        let xml = r#"
<host starttime="1589292535" endtime="NOT A NUMBER">
    <status state="down" reason="no-response" reason_ttl="0"/>
    <address addr="192.168.59.234" addrtype="ipv4"/>
</host>
        "#;
        let doc = Document::parse(&xml).unwrap();
        let ele = doc.root_element();
        let host_err = Host::parse(ele).unwrap_err();

        assert_eq!(
            host_err.to_string(),
            "error parsing Nmap XML output: failed to parse host end time"
        );
    }
}
