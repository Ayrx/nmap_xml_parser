//!Host related structs and enums.
use macaddr::MacAddr6;
use roxmltree::Node;
use std::net::IpAddr;
use std::str::FromStr;
use strum_macros::{Display, EnumString};

use crate::port::PortInfo;
use crate::Error;

#[derive(Display, Clone, Debug, PartialEq)]
pub enum Address {
    IpAddr(IpAddr),
    MacAddr(MacAddr6),
}

#[derive(Clone, Debug)]
pub struct Host {
    pub(crate) addresses: Vec<Address>,
    pub(crate) scripts: Vec<Script>,
    pub status: HostStatus,
    pub(crate) host_names: Vec<Hostname>,
    pub port_info: PortInfo,
    pub scan_start_time: Option<i64>,
    pub scan_end_time: Option<i64>,
    pub tcpsequence: Option<TcpSequence>,
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
        let mut scripts = Vec::new();
        let mut addresses = Vec::new();
        let mut tcpsequence = None;

        for child in node.children() {
            match child.tag_name().name() {
                "address" => addresses.push(parse_address_node(child)?),
                "status" => status = Some(HostStatus::parse(child)?),
                "hostnames" => host_names = parse_hostnames_node(child)?,
                "hostscript" => scripts = parse_hostscript_node(child)?,
                "ports" => port_info = PortInfo::parse(child)?,
                "tcpsequence" => tcpsequence = Some(TcpSequence::parse(child)?),
                _ => {}
            }
        }

        let status = status.ok_or_else(|| Error::from("expected `status` node for host"))?;

        Ok(Host {
            addresses,
            scripts,
            status,
            host_names,
            port_info,
            scan_start_time,
            scan_end_time,
            tcpsequence,
        })
    }

    ///Returns an iterator over the addresses associated with this host.
    pub fn addresses(&self) -> std::slice::Iter<Address> {
        self.addresses.iter()
    }

    ///Returns an iterator over the scripts associated with this host.
    pub fn scripts(&self) -> std::slice::Iter<Script> {
        self.scripts.iter()
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
        "mac" => {
            let a = addr
                .parse::<MacAddr6>()
                .map_err(|_| Error::from("failed to parse MAC address"))?;
            Ok(Address::MacAddr(a))
        }
        _ => {
            let a = addr
                .parse::<IpAddr>()
                .map_err(|_| Error::from("failed to parse IP address"))?;
            Ok(Address::IpAddr(a))
        }
    }
}

fn parse_hostscript_node(node: Node) -> Result<Vec<Script>, Error> {
    let mut r = Vec::new();

    for child in node.children() {
        if child.tag_name().name() == "script" {
            r.push(Script::parse(child)?);
        }
    }

    Ok(r)
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

#[derive(Clone, Debug, PartialEq)]
pub struct Script {
    pub id: String,
    pub output: String,
}

impl Script {
    fn parse(node: Node) -> Result<Self, Error> {
        let id = node
            .attribute("id")
            .ok_or_else(|| Error::from("expected `id` attribute in `script` node"))?
            .to_string();

        let output = node
            .attribute("output")
            .ok_or_else(|| Error::from("expected `output` attribute in `script` node"))?
            .to_string();

        Ok(Script { id, output })
    }
}

#[derive(EnumString, Display, Clone, Debug, PartialEq)]
pub enum TcpDifficulty {
    #[strum(serialize = "Trivial joke")]
    Trivial,
    #[strum(serialize = "Easy")]
    Easy,
    #[strum(serialize = "Medium")]
    Medium,
    #[strum(serialize = "Formidable")]
    Formidable,
    #[strum(serialize = "Worthy challenge")]
    Worthy,
    #[strum(serialize = "Good luck!")]
    Good,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TcpSequence {
    pub index: u32,
    pub values: [u32; 6],
    pub difficulty: TcpDifficulty,
}

impl TcpSequence {
    fn parse(node: Node) -> Result<Self, Error> {
        let index = node
            .attribute("index")
            .ok_or_else(|| Error::from("expected `index` attribute in `tcpsequence` node"))
            .and_then(|s| {
                s.parse::<u32>()
                    .map_err(|_| Error::from("failed to parse `index`"))
            })?;

        let values = node
            .attribute("values")
            .ok_or_else(|| Error::from("expected `values` attribute in `tcpsequence` node"))
            .and_then(|s| {
                let mut arr: [u32; 6] = [0; 6];
                for (elem, val) in arr.iter_mut().zip(s.split(",")) {
                    //*elem = val.parse::<u32>().expect("Failed to parse `values` in `tcpsequence` node");
                    *elem = u32::from_str_radix(val, 16).unwrap();
                }
                Ok(arr)
            })?;

        let d = node
            .attribute("difficulty")
            .ok_or_else(|| Error::from("expected `difficulty` attribute in `tcpsequence` node"))?;
        let difficulty = TcpDifficulty::from_str(d)
            .map_err(|_| Error::from("failed to parse tcp sequence prediction difficulty"))?;

        Ok(TcpSequence {
            index,
            values,
            difficulty,
        })
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
    fn host_with_multiple_script_output() {
        let xml = r#"
<host starttime="1623467939" endtime="1623467939"><status state="up" reason="conn-refused" reason_ttl="0"/>
<address addr="192.168.1.70" addrtype="ipv4"/>
<hostscript><script id="smb-print-text" output="false">false</script><script id="smb2-time" output="&#xa;  date: 2021-06-12T03:17:58&#xa;  start_date: N/A"><elem key="date">2021-06-12T03:17:58</elem>
<elem key="start_date">N/A</elem>
</script></hostscript><times srtt="5263" rttvar="4662" to="100000"/>
</host>
        "#;
        let doc = Document::parse(&xml).unwrap();
        let ele = doc.root_element();
        let script_host = Host::parse(ele).unwrap();
        let script_output = script_host.scripts().collect::<Vec<_>>()[0];

        assert_eq!(script_output.id, "smb-print-text");
        assert_eq!(script_output.output, "false");
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
