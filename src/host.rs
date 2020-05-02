//!Host related structs and enums.
use roxmltree::Node;
use std::net::IpAddr;
use std::str::FromStr;
use strum_macros::{Display, EnumString};

use crate::port::PortInfo;
use crate::Error;

pub struct Host {
    pub ip_address: IpAddr,
    pub status: HostStatus,
    pub host_names: Vec<Hostname>,
    pub port_info: PortInfo,
    pub scan_start_time: i64,
    pub scan_end_time: i64,
}

impl Host {
    pub(crate) fn parse(node: Node) -> Result<Self, Error> {
        let scan_start_time = node
            .attribute("starttime")
            .ok_or(Error::InvalidNmapOutput)
            .and_then(|s| s.parse::<i64>().or(Err(Error::InvalidNmapOutput)))?;

        let scan_end_time = node
            .attribute("endtime")
            .ok_or(Error::InvalidNmapOutput)
            .and_then(|s| s.parse::<i64>().or(Err(Error::InvalidNmapOutput)))?;

        let mut ip_address = None;
        let mut status = None;
        let mut host_names = None;
        let mut port_info = None;

        for child in node.children() {
            match child.tag_name().name() {
                "address" => ip_address = Some(parse_address_node(child)?),
                "status" => status = Some(HostStatus::parse(child)?),
                "hostnames" => host_names = Some(parse_hostnames_node(child)?),
                "ports" => port_info = Some(PortInfo::parse(child)?),
                _ => {}
            }
        }

        let ip_address = ip_address.ok_or(Error::InvalidNmapOutput)?;
        let status = status.ok_or(Error::InvalidNmapOutput)?;
        let host_names = host_names.ok_or(Error::InvalidNmapOutput)?;
        let port_info = port_info.ok_or(Error::InvalidNmapOutput)?;

        Ok(Host {
            scan_start_time,
            scan_end_time,
            ip_address,
            status,
            host_names,
            port_info,
        })
    }
}

fn parse_address_node(node: Node) -> Result<IpAddr, Error> {
    node.attribute("addr")
        .ok_or(Error::InvalidNmapOutput)
        .and_then(|s| s.parse::<IpAddr>().or(Err(Error::InvalidNmapOutput)))
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

pub struct HostStatus {
    pub state: HostState,
    pub reason: String,
    pub reason_ttl: u8,
}

impl HostStatus {
    fn parse(node: Node) -> Result<Self, Error> {
        let s = node.attribute("state").ok_or(Error::InvalidNmapOutput)?;
        let state = HostState::from_str(s).or(Err(Error::InvalidNmapOutput))?;

        let reason = node
            .attribute("reason")
            .ok_or(Error::InvalidNmapOutput)?
            .to_string();

        let reason_ttl = node
            .attribute("reason_ttl")
            .ok_or(Error::InvalidNmapOutput)
            .and_then(|s| s.parse::<u8>().or(Err(Error::InvalidNmapOutput)))?;

        Ok(HostStatus {
            state,
            reason,
            reason_ttl,
        })
    }
}

#[derive(EnumString, Display, Debug, PartialEq)]
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

#[derive(EnumString, Display, Debug, PartialEq)]
pub enum HostnameType {
    #[strum(serialize = "user", to_string = "User")]
    User,
    #[strum(serialize = "PTR", to_string = "Dns")]
    Dns,
}

#[derive(Debug, PartialEq)]
pub struct Hostname {
    pub name: String,
    pub source: HostnameType,
}

impl Hostname {
    fn parse(node: Node) -> Result<Self, Error> {
        let name = node
            .attribute("name")
            .ok_or(Error::InvalidNmapOutput)?
            .to_string();

        let s = node.attribute("type").ok_or(Error::InvalidNmapOutput)?;
        let source = HostnameType::from_str(s).or(Err(Error::InvalidNmapOutput))?;

        Ok(Hostname { name, source })
    }
}
