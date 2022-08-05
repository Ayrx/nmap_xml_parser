//!Port related structs and enums.
use const_format::formatcp;
use roxmltree::Node;
use std::str::FromStr;
use strum_macros::{Display, EnumString};

use crate::util::{from_node_attr, node_attr_as_string, parse_node_attr};
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
        let protocol = from_node_attr!(node, "port", "protocol", PortProtocol);

        let port_number = parse_node_attr!(node, "port", "portid", u16);

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
        let state = from_node_attr!(node, "port", "state", PortState);

        let reason = node_attr_as_string!(node, "port", "reason");

        let reason_ttl = parse_node_attr!(node, "port", "reason_ttl", u8);

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
        let name = node_attr_as_string!(node, "service", "name");

        let confidence_level = parse_node_attr!(node, "service", "conf", u8);

        let method = from_node_attr!(node, "service", "method", ServiceMethod);

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
