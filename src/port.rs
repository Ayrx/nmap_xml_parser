//!Port related structs and enums.
use roxmltree::Node;
use std::str::FromStr;
use strum_macros::{Display, EnumString};

use crate::util::node_attr_as_string;
use crate::util::parse_node_attr;
use crate::Error;

#[derive(Clone, Debug, Default)]
pub struct PortInfo {
    pub(crate) ports: Vec<Port>,
}

impl PortInfo {
    pub(crate) fn parse(node: Node) -> Result<Self, Error> {
        let mut ports = Vec::new();

        for child in node.children() {
            #[allow(clippy::single_match)]
            match child.tag_name().name() {
                "port" => ports.push(Port::parse(child)?),
                _ => {}
            }
        }

        Ok(PortInfo { ports })
    }

    ///Returns an iterator over the ports associated with this host.
    pub fn ports(&self) -> std::slice::Iter<Port> {
        self.ports.iter()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Port {
    pub protocol: PortProtocol,
    pub port_number: u16,
    pub status: PortStatus,
    pub service_info: Option<ServiceInfo>,
}

impl Port {
    fn parse(node: Node) -> Result<Self, Error> {
        let s = node
            .attribute("protocol")
            .ok_or_else(|| Error::from("expected `protocol` attribute in `port` node"))?;
        let protocol =
            PortProtocol::from_str(s).map_err(|_| Error::from("failed to parse port protocol"))?;

        let port_number = parse_node_attr::<u16>(node, "portid").unwrap();

        let mut status = None;
        let mut service_info = None;

        for child in node.children() {
            match child.tag_name().name() {
                "state" => status = Some(PortStatus::parse(child)?),
                "service" => service_info = Some(ServiceInfo::parse(child)?),
                _ => {}
            }
        }

        let status = status.ok_or_else(|| Error::from("expected `state` attribute for port"))?;

        Ok(Port {
            protocol,
            port_number,
            status,
            service_info,
        })
    }
}

#[derive(EnumString, Display, Clone, Debug, PartialEq)]
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

#[derive(Clone, Debug, PartialEq)]
pub struct PortStatus {
    pub state: PortState,
    pub reason: String,
    pub reason_ttl: u8,
}

impl PortStatus {
    fn parse(node: Node) -> Result<Self, Error> {
        let s = node
            .attribute("state")
            .ok_or_else(|| Error::from("expected `state` attribute for port"))?;
        let state =
            PortState::from_str(s).map_err(|_| Error::from("failed to parse port state"))?;

        let reason = node_attr_as_string(node, "reason").unwrap();

        let reason_ttl = parse_node_attr::<u8>(node, "reason_ttl").unwrap();

        Ok(PortStatus {
            state,
            reason,
            reason_ttl,
        })
    }
}

#[derive(EnumString, Display, Clone, Debug, PartialEq)]
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

#[derive(Clone, Debug, PartialEq)]
pub struct ServiceInfo {
    pub name: String,
    pub confidence_level: u8,
    pub method: ServiceMethod,
}

impl ServiceInfo {
    fn parse(node: Node) -> Result<Self, Error> {
        let name = node
            .attribute("name")
            .ok_or_else(|| Error::from("expected `name` attribute for service"))?
            .to_string();

        let confidence_level = node
            .attribute("conf")
            .ok_or_else(|| Error::from("expected `conf` attribute for service"))
            .and_then(|s| {
                s.parse::<u8>()
                    .map_err(|_| Error::from("failed to parse port reason_ttl"))
            })?;

        let s = node
            .attribute("method")
            .ok_or_else(|| Error::from("expected `method` attribute for service"))?;
        let method = ServiceMethod::from_str(s)
            .map_err(|_| Error::from("failed to parse service method"))?;

        Ok(ServiceInfo {
            name,
            confidence_level,
            method,
        })
    }
}

#[derive(EnumString, Display, Clone, Debug, PartialEq)]
pub enum ServiceMethod {
    #[strum(serialize = "table")]
    Table,
    #[strum(serialize = "probed")]
    Probe,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PortUsed {
    pub state: PortState,
    pub proto: PortProtocol,
    pub port_number: u16,
}

impl PortUsed {
    pub fn parse(node: Node) -> Result<Self, Error> {
        let s = node
            .attribute("state")
            .ok_or_else(|| Error::from("expected `state` attribute in `portused` node"))?;
        let state =
            PortState::from_str(s).map_err(|_| Error::from("failed to parse port state"))?;

        let p = node
            .attribute("proto")
            .ok_or_else(|| Error::from("expected `proto` attribute in `portused` node"))?;
        let proto =
            PortProtocol::from_str(p).map_err(|_| Error::from("failed to parse port protocol"))?;

        let port_number = node
            .attribute("portid")
            .ok_or_else(|| Error::from("expected `port_id` attribute in `portused` node"))
            .and_then(|s| {
                s.parse::<u16>()
                    .map_err(|_| Error::from("failed to parse portused port_id"))
            })?;

        Ok(PortUsed {
            state,
            proto,
            port_number,
        })
    }
}
