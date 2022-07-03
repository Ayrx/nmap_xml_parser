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
    static ref NMAP_HOST_DOWN: NmapResults = {
        let mut path = PathBuf::new();
        path.push(&std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.push("tests/host-down.xml");
        let content = fs::read_to_string(path).unwrap();
        NmapResults::parse(&content).unwrap()
    };
    static ref NMAP_INCOMPLETE_SCAN: NmapResults = {
        let mut path = PathBuf::new();
        path.push(&std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.push("tests/incomplete_scan.xml");
        let content = fs::read_to_string(path).unwrap();
        NmapResults::parse(&content).unwrap()
    };
    static ref NMAP_VERBOSE_SCAN: NmapResults = {
        let mut path = PathBuf::new();
        path.push(&std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.push("tests/verbose_scan.xml");
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
    assert_eq!(NMAP_TEST_XML.scan_end_time, Some(1588318814));
}

#[test]
fn no_end_time() {
    assert_eq!(NMAP_INCOMPLETE_SCAN.scan_end_time, None);
}

#[test]
fn host_start_time() {
    let host = NMAP_TEST_XML.hosts().next().unwrap();
    assert_eq!(host.scan_start_time, Some(1588318812));
}

#[test]
fn host_end_time() {
    let host = NMAP_TEST_XML.hosts().next().unwrap();
    assert_eq!(host.scan_end_time, Some(1588318814));
}

#[test]
fn host_ip_address() {
    let ip: std::net::IpAddr = "45.33.32.156".parse().unwrap();

    let host = NMAP_TEST_XML.hosts().next().unwrap();
    assert!(host.addresses().len() == 1);

    let ip_addr = host.addresses().next().unwrap();
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
    let h1 = host::Hostname {
        name: "scanme.nmap.org".to_string(),
        source: host::HostnameType::User,
    };

    let h2 = host::Hostname {
        name: "scanme.nmap.org".to_string(),
        source: host::HostnameType::Dns,
    };

    expected.push(&h1);
    expected.push(&h2);

    assert!(!(host.host_names().count() == 0));
    assert!(vectors_eq(&host.host_names().collect(), &expected));
}

#[test]
fn host_portinfo_ports() {
    let host = NMAP_TEST_XML.hosts().next().unwrap();

    let mut expected = Vec::new();

    let p1 = port::Port {
        protocol: port::PortProtocol::Tcp,
        port_number: 22,
        status: port::PortStatus {
            state: port::PortState::Open,
            reason: "syn-ack".to_string(),
            reason_ttl: 53,
        },
        service_info: Some(port::ServiceInfo {
            name: "ssh".to_string(),
            method: port::ServiceMethod::Table,
            confidence_level: 3,
        }),
    };

    let p2 = port::Port {
        protocol: port::PortProtocol::Tcp,
        port_number: 80,
        status: port::PortStatus {
            state: port::PortState::Open,
            reason: "syn-ack".to_string(),
            reason_ttl: 52,
        },
        service_info: Some(port::ServiceInfo {
            name: "http".to_string(),
            method: port::ServiceMethod::Table,
            confidence_level: 3,
        }),
    };

    let p3 = port::Port {
        protocol: port::PortProtocol::Tcp,
        port_number: 9929,
        status: port::PortStatus {
            state: port::PortState::Open,
            reason: "syn-ack".to_string(),
            reason_ttl: 53,
        },
        service_info: Some(port::ServiceInfo {
            name: "nping-echo".to_string(),
            method: port::ServiceMethod::Table,
            confidence_level: 3,
        }),
    };

    let p4 = port::Port {
        protocol: port::PortProtocol::Tcp,
        port_number: 31337,
        status: port::PortStatus {
            state: port::PortState::Open,
            reason: "syn-ack".to_string(),
            reason_ttl: 52,
        },
        service_info: Some(port::ServiceInfo {
            name: "Elite".to_string(),
            method: port::ServiceMethod::Table,
            confidence_level: 3,
        }),
    };

    expected.push(&p1);
    expected.push(&p2);
    expected.push(&p3);
    expected.push(&p4);

    assert!(!(host.port_info.ports().count() == 0));
    assert!(vectors_eq(&host.port_info.ports().collect(), &expected));
}

#[test]
fn test_issue_one() {
    let ip: std::net::IpAddr = "192.168.59.138".parse().unwrap();
    let mac: macaddr::MacAddr6 = "00:0C:29:71:23:2B".parse().unwrap();

    let host = NMAP_ISSUE_ONE.hosts().next().unwrap();
    assert!(host.addresses().count() == 2);

    let mut addresses = host.addresses();

    let ip_addr = addresses.next().unwrap();
    println!("{:?}", ip_addr);
    match ip_addr {
        host::Address::IpAddr(s) => assert_eq!(s, &ip),
        host::Address::MacAddr(_) => assert!(false),
    }

    let mac_addr = addresses.next().unwrap();
    println!("{:?}", mac_addr);
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

#[test]
fn test_host_down() {
    use host::HostState;
    eprintln!("{:?}", *NMAP_HOST_DOWN);

    for host in NMAP_HOST_DOWN.hosts() {
        assert_eq!(host.status.state, HostState::Down);
    }
}

#[test]
fn test_tcpsequence() {
    use host::TcpDifficulty;

    let expected_values: [u32; 6] = [
        1224835593, 1220799469, 1230646911, 1228862220, 1223508915, 1230674700,
    ];

    let expected = host::TcpSequence {
        index: 199,
        difficulty: TcpDifficulty::Good,
        values: expected_values,
    };

    let tcpsequence = NMAP_VERBOSE_SCAN
        .hosts()
        .next()
        .unwrap()
        .tcpsequence
        .as_ref();

    assert_eq!(tcpsequence.unwrap(), &expected);
}

#[test]
fn test_ipidsequence() {
    let expected_values: [u32; 6] = [
        0, 0, 0, 0, 0, 0
    ];

    let expected = host::IpIdSequence {
        class: String::from("All zeros"),
        values: expected_values
    };

    let ipidsequence = NMAP_VERBOSE_SCAN
        .hosts()
        .next()
        .unwrap()
        .ipidsequence
        .as_ref();

    assert_eq!(ipidsequence.unwrap(), &expected);

}
