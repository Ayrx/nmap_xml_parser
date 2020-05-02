//!Port related structs and enums.
use roxmltree::Node;
use std::str::FromStr;
use strum_macros::{Display, EnumString};

use crate::Error;

pub struct PortInfo {
    pub ports: Vec<Port>,
}

impl PortInfo {
    pub(crate) fn parse(node: Node) -> Result<Self, Error> {
        let mut ports = Vec::new();

        for child in node.children() {
            match child.tag_name().name() {
                "port" => ports.push(Port::parse(child)?),
                _ => {}
            }
        }

        Ok(PortInfo { ports })
    }
}

#[derive(Debug, PartialEq)]
pub struct Port {
    pub protocol: PortProtocol,
    pub port_number: u16,
    pub status: PortStatus,
    pub service_info: ServiceInfo,
}

impl Port {
    fn parse(node: Node) -> Result<Self, Error> {
        let s = node.attribute("protocol").ok_or(Error::InvalidNmapOutput)?;
        let protocol = PortProtocol::from_str(s).or(Err(Error::InvalidNmapOutput))?;

        let port_number = node
            .attribute("portid")
            .ok_or(Error::InvalidNmapOutput)
            .and_then(|s| s.parse::<u16>().or(Err(Error::InvalidNmapOutput)))?;

        let mut status = None;
        let mut service_info = None;

        for child in node.children() {
            match child.tag_name().name() {
                "state" => status = Some(PortStatus::parse(child)?),
                "service" => service_info = Some(ServiceInfo::parse(child)?),
                _ => {}
            }
        }

        let status = status.ok_or(Error::InvalidNmapOutput)?;
        let service_info = service_info.ok_or(Error::InvalidNmapOutput)?;

        Ok(Port {
            protocol,
            port_number,
            status,
            service_info,
        })
    }
}

#[derive(EnumString, Display, Debug, PartialEq)]
pub enum PortProtocol {
    #[strum(serialize = "ip")]
    Ip,
    #[strum(serialize = "tcp")]
    Tcp,
    #[strum(serialize = "udp")]
    Udp,
    #[strum(serialize = "sctp")]
    Sctp,
}

#[derive(Debug, PartialEq)]
pub struct PortStatus {
    pub state: PortState,
    pub reason: String,
    pub reason_ttl: u8,
}

impl PortStatus {
    fn parse(node: Node) -> Result<Self, Error> {
        let s = node.attribute("state").ok_or(Error::InvalidNmapOutput)?;
        let state = PortState::from_str(s).or(Err(Error::InvalidNmapOutput))?;

        let reason = node
            .attribute("reason")
            .ok_or(Error::InvalidNmapOutput)?
            .to_string();

        let reason_ttl = node
            .attribute("reason_ttl")
            .ok_or(Error::InvalidNmapOutput)
            .and_then(|s| s.parse::<u8>().or(Err(Error::InvalidNmapOutput)))?;

        Ok(PortStatus {
            state,
            reason,
            reason_ttl,
        })
    }
}

#[derive(EnumString, Display, Debug, PartialEq)]
pub enum PortState {
    #[strum(serialize = "open")]
    Open,
    #[strum(serialize = "closed")]
    Closed,
    #[strum(serialize = "filtered")]
    Filtered,
    #[strum(serialize = "unfiltered")]
    Unfiltered,
    #[strum(serialize = "open|filtered")]
    OpenFiltered,
    #[strum(serialize = "close|filtered")]
    CloseFiltered,
}

#[derive(Debug, PartialEq)]
pub struct ServiceInfo {
    pub name: String,
    pub confidence_level: u8,
    pub method: ServiceMethod,
}

impl ServiceInfo {
    fn parse(node: Node) -> Result<Self, Error> {
        let name = node
            .attribute("name")
            .ok_or(Error::InvalidNmapOutput)?
            .to_string();

        let confidence_level = node
            .attribute("conf")
            .ok_or(Error::InvalidNmapOutput)
            .and_then(|s| s.parse::<u8>().or(Err(Error::InvalidNmapOutput)))?;

        let s = node.attribute("method").ok_or(Error::InvalidNmapOutput)?;
        let method = ServiceMethod::from_str(s).or(Err(Error::InvalidNmapOutput))?;

        Ok(ServiceInfo {
            name,
            confidence_level,
            method,
        })
    }
}

#[derive(EnumString, Display, Debug, PartialEq)]
pub enum ServiceMethod {
    #[strum(serialize = "table")]
    Table,
    #[strum(serialize = "probed")]
    Probe,
}
