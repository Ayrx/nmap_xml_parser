#[macro_use]
extern crate lazy_static;

use nmap_xml_parser::{host, port, NmapResults};
use std::fs;
use std::path::PathBuf;

lazy_static! {
    static ref NMAP_TEST_XML: NmapResults = {
        let mut path = PathBuf::new();
        path.push(&std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.push("tests/test.xml");
        let content = fs::read_to_string(path).unwrap();
        NmapResults::parse(&content).unwrap()
    };
    static ref NMAP_ISSUE_ONE: NmapResults = {
        let mut path = PathBuf::new();
        path.push(&std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.push("tests/issue_1.xml");
        let content = fs::read_to_string(path).unwrap();
        NmapResults::parse(&content).unwrap()
    };
}

fn vectors_eq<T: PartialEq>(a: &Vec<T>, b: &Vec<T>) -> bool {
    let matching = a.iter().zip(b.iter()).filter(|&(a, b)| a == b).count();
    matching == a.len() || matching == b.len()
}

#[test]
fn start_time() {
    assert_eq!(NMAP_TEST_XML.scan_start_time, 1588318812);
}

#[test]
fn end_time() {
    assert_eq!(NMAP_TEST_XML.scan_end_time, 1588318814);
}

#[test]
fn host_start_time() {
    let host = NMAP_TEST_XML.hosts().next().unwrap();
    assert_eq!(host.scan_start_time, 1588318812);
}

#[test]
fn host_end_time() {
    let host = NMAP_TEST_XML.hosts().next().unwrap();
    assert_eq!(host.scan_end_time, 1588318814);
}

#[test]
fn host_ip_address() {
    let ip: std::net::IpAddr = "45.33.32.156".parse().unwrap();

    let host = NMAP_TEST_XML.hosts().next().unwrap();
    assert!(host.addresses.len() == 1);

    let ip_addr = host.addresses.get(0).unwrap();
    match ip_addr {
        host::Address::IpAddr(s) => assert_eq!(s, &ip),
        host::Address::MacAddr(_) => assert!(false),
    }
}

#[test]
fn host_status() {
    let host = NMAP_TEST_XML.hosts().next().unwrap();
    assert_eq!(host.status.reason, "echo-reply");
    assert_eq!(host.status.reason_ttl, 53);
    assert_eq!(host.status.state, host::HostState::Up);
}

#[test]
fn host_hostnames() {
    let host = NMAP_TEST_XML.hosts().next().unwrap();

    let mut expected = Vec::new();
    expected.push(host::Hostname {
        name: "scanme.nmap.org".to_string(),
        source: host::HostnameType::User,
    });

    expected.push(host::Hostname {
        name: "scanme.nmap.org".to_string(),
        source: host::HostnameType::Dns,
    });

    assert!(!host.host_names.is_empty());
    assert!(vectors_eq(&host.host_names, &expected));
}

#[test]
fn host_portinfo_ports() {
    let host = NMAP_TEST_XML.hosts().next().unwrap();

    let mut expected = Vec::new();

    expected.push(port::Port {
        protocol: port::PortProtocol::Tcp,
        port_number: 22,
        status: port::PortStatus {
            state: port::PortState::Open,
            reason: "syn-ack".to_string(),
            reason_ttl: 53,
        },
        service_info: port::ServiceInfo {
            name: "ssh".to_string(),
            method: port::ServiceMethod::Table,
            confidence_level: 3,
        },
    });

    expected.push(port::Port {
        protocol: port::PortProtocol::Tcp,
        port_number: 80,
        status: port::PortStatus {
            state: port::PortState::Open,
            reason: "syn-ack".to_string(),
            reason_ttl: 52,
        },
        service_info: port::ServiceInfo {
            name: "http".to_string(),
            method: port::ServiceMethod::Table,
            confidence_level: 3,
        },
    });

    expected.push(port::Port {
        protocol: port::PortProtocol::Tcp,
        port_number: 9929,
        status: port::PortStatus {
            state: port::PortState::Open,
            reason: "syn-ack".to_string(),
            reason_ttl: 53,
        },
        service_info: port::ServiceInfo {
            name: "nping-echo".to_string(),
            method: port::ServiceMethod::Table,
            confidence_level: 3,
        },
    });

    expected.push(port::Port {
        protocol: port::PortProtocol::Tcp,
        port_number: 31337,
        status: port::PortStatus {
            state: port::PortState::Open,
            reason: "syn-ack".to_string(),
            reason_ttl: 52,
        },
        service_info: port::ServiceInfo {
            name: "Elite".to_string(),
            method: port::ServiceMethod::Table,
            confidence_level: 3,
        },
    });

    assert!(!host.port_info.ports.is_empty());
    assert!(vectors_eq(&host.port_info.ports, &expected));
}

#[test]
fn test_issue_one() {
    let ip: std::net::IpAddr = "192.168.59.138".parse().unwrap();
    let mac = "00:0C:29:71:23:2B".to_string();

    let host = NMAP_ISSUE_ONE.hosts().next().unwrap();
    assert!(host.addresses.len() == 2);

    let ip_addr = host.addresses.get(0).unwrap();
    match ip_addr {
        host::Address::IpAddr(s) => assert_eq!(s, &ip),
        host::Address::MacAddr(_) => assert!(false),
    }

    let mac_addr = host.addresses.get(1).unwrap();
    match mac_addr {
        host::Address::IpAddr(_) => assert!(false),
        host::Address::MacAddr(s) => assert_eq!(s, &mac),
    }
}

#[test]
fn test_iter_ports() {
    let mut v = Vec::new();

    for (_, port) in NMAP_TEST_XML.iter_ports() {
        v.push(port.port_number);
    }

    let expected = vec![22, 80, 9929, 31337];
    assert!(vectors_eq(&v, &expected));
}
