#[macro_use]
extern crate lazy_static;

use nmap_xml_parser::host::*;
use nmap_xml_parser::port::*;
use std::sync::Arc;

use nmap_xml_parser::{HostDetails, NmapResults, Port};
use std::fs;
use std::path::PathBuf;

lazy_static! {
    static ref NMAP: NmapResults = {
        let mut path = PathBuf::new();
        path.push(&std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.push("tests/test.xml");
        let content = fs::read_to_string(path).unwrap();
        NmapResults::parse(&content).unwrap()
    };
}

#[test]
fn iter() {
    use HostState::*;
    use HostnameType::*;
    use PortProtocol::*;
    use PortState::*;
    use ServiceMethod::*;
    let nmap = NMAP.clone();
    let vector: Vec<(Arc<HostDetails>, Port)> = nmap.into_iter().collect();

    let host_details = Arc::new(HostDetails {
        ip_address: "45.33.32.156".parse().unwrap(),
        status: HostStatus {
            state: Up,
            reason: "echo-reply".to_string(),
            reason_ttl: 53,
        },
        host_names: vec![
            Hostname {
                name: "scanme.nmap.org".to_string(),
                source: User,
            },
            Hostname {
                name: "scanme.nmap.org".to_string(),
                source: Dns,
            },
        ],
        scan_start_time: 1_588_318_812,
        scan_end_time: 1_588_318_814,
    });

    let correct = vec![
        (
            host_details.clone(),
            Port {
                protocol: Tcp,
                port_number: 22,
                status: PortStatus {
                    state: Open,
                    reason: "syn-ack".to_string(),
                    reason_ttl: 53,
                },
                service_info: ServiceInfo {
                    name: "ssh".to_string(),
                    confidence_level: 3,
                    method: Table,
                },
            },
        ),
        (
            host_details.clone(),
            Port {
                protocol: Tcp,
                port_number: 80,
                status: PortStatus {
                    state: Open,
                    reason: "syn-ack".to_string(),
                    reason_ttl: 52,
                },
                service_info: ServiceInfo {
                    name: "http".to_string(),
                    confidence_level: 3,
                    method: Table,
                },
            },
        ),
        (
            host_details.clone(),
            Port {
                protocol: Tcp,
                port_number: 9929,
                status: PortStatus {
                    state: Open,
                    reason: "syn-ack".to_string(),
                    reason_ttl: 53,
                },
                service_info: ServiceInfo {
                    name: "nping-echo".to_string(),
                    confidence_level: 3,
                    method: Table,
                },
            },
        ),
        (
            host_details,
            Port {
                protocol: Tcp,
                port_number: 31337,
                status: PortStatus {
                    state: Open,
                    reason: "syn-ack".to_string(),
                    reason_ttl: 52,
                },
                service_info: ServiceInfo {
                    name: "Elite".to_string(),
                    confidence_level: 3,
                    method: Table,
                },
            },
        ),
    ];

    eprintln!("vector: {:?}", vector);

    assert_eq!(vector, correct);
}
