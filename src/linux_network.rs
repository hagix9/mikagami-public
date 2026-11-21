//! Linux-only production NetworkBackend and platform-independent mapping tests.

use super::{ActionDiagnostic, RawGarpOutcome, RawVipObservation};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

const GARP_TIMEOUT_MS: u64 = 3_000;
static NEXT_NETLINK_SEQUENCE: AtomicU32 = AtomicU32::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxNetworkConfigError(String);

impl std::fmt::Display for LinuxNetworkConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for LinuxNetworkConfigError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxNetworkConfig {
    pub(crate) interface: String,
    pub(crate) vip: Ipv4Addr,
    pub(crate) prefix_len: u8,
    pub(crate) arping_path: PathBuf,
    pub(crate) arp_count: u32,
}

impl LinuxNetworkConfig {
    pub(crate) fn new(
        interface: impl Into<String>,
        vip: IpAddr,
        prefix_len: u8,
        arping_path: impl Into<PathBuf>,
        arp_count: u32,
    ) -> Result<Self, LinuxNetworkConfigError> {
        let interface = interface.into();
        let arping_path = arping_path.into();
        let vip = match vip {
            IpAddr::V4(value) => value,
            IpAddr::V6(_) => {
                return Err(LinuxNetworkConfigError(
                    "Linux NetworkBackend supports IPv4 only".into(),
                ));
            }
        };
        if interface.trim().is_empty() || interface.len() > 15 || interface.as_bytes().contains(&0)
        {
            return Err(LinuxNetworkConfigError(
                "interface must be a non-empty Linux interface name".into(),
            ));
        }
        if prefix_len > 32 {
            return Err(LinuxNetworkConfigError(
                "IPv4 prefix length must be between 0 and 32".into(),
            ));
        }
        if !arping_path.is_absolute() {
            return Err(LinuxNetworkConfigError(
                "arping path must be absolute".into(),
            ));
        }
        if arp_count == 0 {
            return Err(LinuxNetworkConfigError(
                "arping count must be greater than zero".into(),
            ));
        }
        Ok(Self {
            interface,
            vip,
            prefix_len,
            arping_path,
            arp_count,
        })
    }

    pub(crate) fn from_cidr(
        interface: impl Into<String>,
        cidr: &str,
        arping_path: impl Into<PathBuf>,
        arp_count: u32,
    ) -> Result<Self, LinuxNetworkConfigError> {
        let (address, prefix) = cidr
            .split_once('/')
            .ok_or_else(|| LinuxNetworkConfigError("VIP must use IPv4/prefix notation".into()))?;
        let vip = address
            .parse::<IpAddr>()
            .map_err(|_| LinuxNetworkConfigError("VIP must contain a valid IP address".into()))?;
        let prefix_len = prefix
            .parse::<u8>()
            .map_err(|_| LinuxNetworkConfigError("VIP prefix length must be an integer".into()))?;
        Self::new(interface, vip, prefix_len, arping_path, arp_count)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArpingArguments {
    pub(crate) interface: String,
    pub(crate) count: u32,
    pub(crate) vip: Ipv4Addr,
}

impl ArpingArguments {
    fn as_strings(&self) -> Vec<String> {
        vec![
            "-U".into(),
            "-I".into(),
            self.interface.clone(),
            "-c".into(),
            self.count.to_string(),
            self.vip.to_string(),
        ]
    }
}

fn arping_arguments(config: &LinuxNetworkConfig) -> ArpingArguments {
    ArpingArguments {
        interface: config.interface.clone(),
        count: config.arp_count,
        vip: config.vip,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArpingProcessResult {
    ExitZero,
    ExitNonZero,
    Signaled,
    TimedOutCleaned,
    TimedOutReapedAfterKillFailure,
    WaitFailedCleaned,
    CleanupFailed,
    SpawnFailed,
}

fn map_arping_result(result: ArpingProcessResult) -> (ActionDiagnostic, RawGarpOutcome) {
    match result {
        ArpingProcessResult::ExitZero => (ActionDiagnostic::Success, RawGarpOutcome::Succeeded),
        ArpingProcessResult::TimedOutCleaned
        | ArpingProcessResult::TimedOutReapedAfterKillFailure => {
            (ActionDiagnostic::Timeout, RawGarpOutcome::Failed)
        }
        ArpingProcessResult::Signaled => (ActionDiagnostic::Interrupted, RawGarpOutcome::Failed),
        ArpingProcessResult::ExitNonZero | ArpingProcessResult::SpawnFailed => (
            ActionDiagnostic::Error("arping failed".into()),
            RawGarpOutcome::Failed,
        ),
        ArpingProcessResult::WaitFailedCleaned => (
            ActionDiagnostic::Error("arping wait failed".into()),
            RawGarpOutcome::Failed,
        ),
        ArpingProcessResult::CleanupFailed => (
            ActionDiagnostic::Error("arping cleanup uncertain".into()),
            RawGarpOutcome::Failed,
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressAttributeKind {
    LocalIpv4(Ipv4Addr),
    AddressIpv4(Ipv4Addr),
    LocalIpv6,
    AddressIpv6,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalAddressObservation {
    LocalIpv4(Ipv4Addr),
    NonIpv4OrIrrelevant,
    MalformedOrAmbiguous,
}

fn extract_local_ipv4(attributes: &[AddressAttributeKind]) -> LocalAddressObservation {
    let mut local_ipv4 = None;
    let mut address_ipv4 = None;
    let mut local_ipv6 = false;
    let mut address_ipv6 = false;

    for attribute in attributes {
        match attribute {
            AddressAttributeKind::LocalIpv4(address) => {
                if local_ipv4.is_some_and(|current| current != *address) {
                    return LocalAddressObservation::MalformedOrAmbiguous;
                }
                local_ipv4 = Some(*address);
            }
            AddressAttributeKind::AddressIpv4(address) => {
                if address_ipv4.is_some_and(|current| current != *address) {
                    return LocalAddressObservation::MalformedOrAmbiguous;
                }
                address_ipv4 = Some(*address);
            }
            AddressAttributeKind::LocalIpv6 => local_ipv6 = true,
            AddressAttributeKind::AddressIpv6 => address_ipv6 = true,
            AddressAttributeKind::Other => {}
        }
    }

    if (local_ipv4.is_some() && local_ipv6) || (address_ipv4.is_some() && address_ipv6) {
        return LocalAddressObservation::MalformedOrAmbiguous;
    }
    if let Some(address) = local_ipv4 {
        return LocalAddressObservation::LocalIpv4(address);
    }
    if local_ipv6 {
        return LocalAddressObservation::NonIpv4OrIrrelevant;
    }
    if let Some(address) = address_ipv4 {
        return LocalAddressObservation::LocalIpv4(address);
    }
    if address_ipv6 {
        return LocalAddressObservation::NonIpv4OrIrrelevant;
    }
    LocalAddressObservation::MalformedOrAmbiguous
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KernelAddress {
    Valid {
        interface_index: u32,
        address: Ipv4Addr,
        prefix_len: u8,
    },
    Other,
    Malformed,
}

fn classify_observation(
    interface_index: Result<u32, ()>,
    addresses: Result<&[KernelAddress], ()>,
    config: &LinuxNetworkConfig,
) -> RawVipObservation {
    let interface_index = match interface_index {
        Ok(value) if value != 0 => value,
        _ => return RawVipObservation::Unavailable,
    };
    let addresses = match addresses {
        Ok(value) => value,
        Err(()) => return RawVipObservation::Unavailable,
    };
    if addresses
        .iter()
        .any(|address| matches!(address, KernelAddress::Malformed))
    {
        return RawVipObservation::Unavailable;
    }
    if addresses.iter().any(|address| {
        matches!(
            address,
            KernelAddress::Valid {
                interface_index: index,
                address,
                prefix_len,
            } if *index == interface_index
                && *address == config.vip
                && *prefix_len == config.prefix_len
        )
    }) {
        RawVipObservation::Present
    } else {
        RawVipObservation::Absent
    }
}

fn filter_kernel_addresses_for_interface(
    interface_index: u32,
    addresses: &[(u32, KernelAddress)],
) -> Vec<KernelAddress> {
    addresses
        .iter()
        .filter(|(index, _)| *index == interface_index)
        .map(|(_, address)| *address)
        .collect()
}

fn next_netlink_sequence() -> u32 {
    loop {
        let current = NEXT_NETLINK_SEQUENCE.load(Ordering::Relaxed);
        let next = if current == u32::MAX { 1 } else { current + 1 };
        if NEXT_NETLINK_SEQUENCE
            .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return current;
        }
    }
}

fn valid_netlink_response(
    expected_sequence: u32,
    response_sequence: u32,
    sender_port: u32,
    sender_groups: u32,
) -> bool {
    expected_sequence != 0
        && response_sequence == expected_sequence
        && sender_port == 0
        && sender_groups == 0
}

fn classify_cleanup_result(
    timeout: bool,
    kill_succeeded: bool,
    wait_succeeded: bool,
) -> ArpingProcessResult {
    match (timeout, kill_succeeded, wait_succeeded) {
        (true, true, true) => ArpingProcessResult::TimedOutCleaned,
        (true, false, true) => ArpingProcessResult::TimedOutReapedAfterKillFailure,
        (false, _, true) => ArpingProcessResult::WaitFailedCleaned,
        (_, _, false) => ArpingProcessResult::CleanupFailed,
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use netlink_packet_core::{
        NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST, NetlinkMessage,
        NetlinkPayload,
    };
    use netlink_packet_route::{
        AddressFamily, RouteNetlinkMessage,
        address::{AddressAttribute, AddressHeaderFlags, AddressMessage, AddressScope},
    };
    use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
    use std::ffi::CString;
    use std::io;
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    pub(crate) struct LinuxNetworkBackend {
        config: LinuxNetworkConfig,
    }

    impl LinuxNetworkBackend {
        pub(crate) fn new(config: LinuxNetworkConfig) -> Result<Self, LinuxNetworkConfigError> {
            let metadata = std::fs::metadata(&config.arping_path).map_err(|_| {
                LinuxNetworkConfigError("configured arping path is not accessible".into())
            })?;
            if !metadata.is_file()
                || std::os::unix::fs::PermissionsExt::mode(&metadata.permissions()) & 0o111 == 0
            {
                return Err(LinuxNetworkConfigError(
                    "configured arping path is not an executable file".into(),
                ));
            }
            Ok(Self { config })
        }

        fn interface_index(&self) -> io::Result<u32> {
            let name = CString::new(self.config.interface.as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface"))?;
            let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if index == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(index)
            }
        }

        fn action(&self, operation: AddressOperation) -> io::Result<()> {
            let index = self.interface_index()?;
            let message = address_message(&self.config, index, operation);
            let sequence = next_netlink_sequence();
            let mut request = NetlinkMessage::from(message);
            request.header.flags = match operation {
                AddressOperation::Add => NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                AddressOperation::Delete => NLM_F_REQUEST | NLM_F_ACK,
                AddressOperation::Dump => NLM_F_REQUEST | NLM_F_DUMP,
            };
            request.header.sequence_number = sequence;
            request.finalize();
            let (socket, local_port) = open_netlink_socket()?;
            request.header.port_number = local_port;
            let destination = SocketAddr::new(0, 0);
            let mut bytes = vec![0; request.buffer_len()];
            request.serialize(&mut bytes);
            socket.send_to(&bytes, &destination, 0)?;
            receive_ack(&socket, sequence, local_port)
        }

        fn observe(&self) -> RawVipObservation {
            let index = match self.interface_index() {
                Ok(value) => value,
                Err(_) => return RawVipObservation::Unavailable,
            };
            let messages = match self.dump_addresses(index) {
                Ok(value) => value,
                Err(_) => return RawVipObservation::Unavailable,
            };
            let addresses: Vec<_> = messages
                .iter()
                .map(|message| {
                    if message.header.index != index {
                        return (message.header.index, KernelAddress::Other);
                    }
                    let attributes: Vec<_> = message
                        .attributes
                        .iter()
                        .map(|attribute| match attribute {
                            AddressAttribute::Local(IpAddr::V4(value)) => {
                                AddressAttributeKind::LocalIpv4(*value)
                            }
                            AddressAttribute::Address(IpAddr::V4(value)) => {
                                AddressAttributeKind::AddressIpv4(*value)
                            }
                            AddressAttribute::Local(IpAddr::V6(_)) => {
                                AddressAttributeKind::LocalIpv6
                            }
                            AddressAttribute::Address(IpAddr::V6(_)) => {
                                AddressAttributeKind::AddressIpv6
                            }
                            _ => AddressAttributeKind::Other,
                        })
                        .collect();
                    match extract_local_ipv4(&attributes) {
                        LocalAddressObservation::LocalIpv4(address) => (
                            message.header.index,
                            KernelAddress::Valid {
                                interface_index: message.header.index,
                                address,
                                prefix_len: message.header.prefix_len,
                            },
                        ),
                        LocalAddressObservation::NonIpv4OrIrrelevant => {
                            (message.header.index, KernelAddress::Other)
                        }
                        LocalAddressObservation::MalformedOrAmbiguous => {
                            (message.header.index, KernelAddress::Malformed)
                        }
                    }
                })
                .collect();
            let relevant = filter_kernel_addresses_for_interface(index, &addresses);
            classify_observation(Ok(index), Ok(&relevant), &self.config)
        }

        fn dump_addresses(&self, index: u32) -> io::Result<Vec<AddressMessage>> {
            let message = address_message(&self.config, index, AddressOperation::Dump);
            let sequence = next_netlink_sequence();
            let mut request = NetlinkMessage::from(message);
            request.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
            request.header.sequence_number = sequence;
            request.finalize();
            let (socket, local_port) = open_netlink_socket()?;
            request.header.port_number = local_port;
            let destination = SocketAddr::new(0, 0);
            let mut bytes = vec![0; request.buffer_len()];
            request.serialize(&mut bytes);
            socket.send_to(&bytes, &destination, 0)?;

            let mut result = Vec::new();
            loop {
                let mut response = vec![0; 64 * 1024];
                let (length, sender) = socket.recv_from(&mut &mut response[..], 0)?;
                if local_port == 0 || !is_kernel_sender(&sender) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected netlink sender",
                    ));
                }
                let mut offset = 0;
                while offset < length {
                    let parsed = NetlinkMessage::<RouteNetlinkMessage>::deserialize(
                        &response[offset..length],
                    )
                    .map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                    })?;
                    let message_length = parsed.header.length as usize;
                    if message_length < 16 || offset + message_length > length {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid netlink length",
                        ));
                    }
                    if !valid_netlink_response(
                        sequence,
                        parsed.header.sequence_number,
                        sender.port_number(),
                        sender.multicast_groups(),
                    ) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unexpected netlink sequence",
                        ));
                    }
                    match parsed.payload {
                        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(message))
                        | NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetAddress(message)) => {
                            result.push(message)
                        }
                        NetlinkPayload::Error(error) => {
                            return if error.raw_code() != 0 {
                                Err(error.to_io())
                            } else {
                                Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "unexpected netlink dump acknowledgement",
                                ))
                            };
                        }
                        NetlinkPayload::Done(_) => return Ok(result),
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "unexpected netlink dump payload",
                            ));
                        }
                    }
                    offset += (message_length + 3) & !3;
                }
            }
        }

        fn execute_garp(&self) -> (ActionDiagnostic, RawGarpOutcome) {
            let arguments = arping_arguments(&self.config).as_strings();
            let mut child = match Command::new(&self.config.arping_path)
                .args(arguments)
                .spawn()
            {
                Ok(child) => child,
                Err(_) => return map_arping_result(ArpingProcessResult::SpawnFailed),
            };
            map_arping_result(wait_for_arping(&mut child))
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum AddressOperation {
        Add,
        Delete,
        Dump,
    }

    fn address_message(
        config: &LinuxNetworkConfig,
        interface_index: u32,
        operation: AddressOperation,
    ) -> RouteNetlinkMessage {
        let attributes = match operation {
            AddressOperation::Dump => Vec::new(),
            AddressOperation::Add | AddressOperation::Delete => vec![
                AddressAttribute::Address(IpAddr::V4(config.vip)),
                AddressAttribute::Local(IpAddr::V4(config.vip)),
            ],
        };
        let mut message = AddressMessage::default();
        message.header.family = AddressFamily::Inet;
        message.header.prefix_len = config.prefix_len;
        message.header.flags = AddressHeaderFlags::empty();
        message.header.scope = AddressScope::Universe;
        message.header.index = interface_index;
        message.attributes = attributes;
        match operation {
            AddressOperation::Add => RouteNetlinkMessage::NewAddress(message),
            AddressOperation::Delete => RouteNetlinkMessage::DelAddress(message),
            AddressOperation::Dump => RouteNetlinkMessage::GetAddress(message),
        }
    }

    fn open_netlink_socket() -> io::Result<(Socket, u32)> {
        let mut socket = Socket::new(NETLINK_ROUTE)?;
        let local = socket.bind_auto()?;
        Ok((socket, local.port_number()))
    }

    fn is_kernel_sender(sender: &SocketAddr) -> bool {
        sender.port_number() == 0 && sender.multicast_groups() == 0
    }

    fn receive_ack(socket: &Socket, sequence: u32, local_port: u32) -> io::Result<()> {
        let mut response = vec![0; 16 * 1024];
        let (length, sender) = socket.recv_from(&mut &mut response[..], 0)?;
        if local_port == 0 || !is_kernel_sender(&sender) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected netlink sender",
            ));
        }
        let mut offset = 0;
        while offset < length {
            let parsed =
                NetlinkMessage::<RouteNetlinkMessage>::deserialize(&response[offset..length])
                    .map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                    })?;
            let message_length = parsed.header.length as usize;
            if message_length < 16 || offset + message_length > length {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid netlink length",
                ));
            }
            if !valid_netlink_response(
                sequence,
                parsed.header.sequence_number,
                sender.port_number(),
                sender.multicast_groups(),
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected netlink sequence",
                ));
            }
            if let NetlinkPayload::Error(error) = parsed.payload {
                if error.raw_code() != 0 {
                    return Err(error.to_io());
                }
                return Ok(());
            }
            offset += (message_length + 3) & !3;
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing netlink acknowledgement",
        ))
    }

    fn cleanup_child(child: &mut Child, timeout: bool) -> ArpingProcessResult {
        let kill_succeeded = child.kill().is_ok();
        let wait_succeeded = child.wait().is_ok();
        classify_cleanup_result(timeout, kill_succeeded, wait_succeeded)
    }

    fn wait_for_arping(child: &mut Child) -> ArpingProcessResult {
        let deadline = Instant::now() + Duration::from_millis(GARP_TIMEOUT_MS);
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return ArpingProcessResult::ExitZero,
                Ok(Some(status)) if status.code().is_none() => {
                    return ArpingProcessResult::Signaled;
                }
                Ok(Some(_)) => return ArpingProcessResult::ExitNonZero,
                Ok(None) if Instant::now() >= deadline => {
                    return cleanup_child(child, true);
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => {
                    return cleanup_child(child, false);
                }
            }
        }
    }

    impl crate::resource_executor::sealed::NetworkBackend for LinuxNetworkBackend {}

    impl crate::resource_executor::NetworkBackend for LinuxNetworkBackend {
        fn request_vip_acquire(&mut self) -> ActionDiagnostic {
            match self.action(AddressOperation::Add) {
                Ok(()) => ActionDiagnostic::Success,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    ActionDiagnostic::Interrupted
                }
                Err(error) => ActionDiagnostic::Error(error.to_string()),
            }
        }

        fn observe_vip(&mut self) -> RawVipObservation {
            self.observe()
        }

        fn request_vip_release(&mut self) -> ActionDiagnostic {
            match self.action(AddressOperation::Delete) {
                Ok(()) => ActionDiagnostic::Success,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    ActionDiagnostic::Interrupted
                }
                Err(error) => ActionDiagnostic::Error(error.to_string()),
            }
        }

        fn send_garp(&mut self) -> (ActionDiagnostic, RawGarpOutcome) {
            self.execute_garp()
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::LinuxNetworkBackend;

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> LinuxNetworkConfig {
        LinuxNetworkConfig::new(
            "eth0",
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
            24,
            "/usr/sbin/arping",
            3,
        )
        .unwrap()
    }

    #[test]
    fn accepts_ipv4_configuration() {
        assert!(
            LinuxNetworkConfig::from_cidr("eth0", "192.0.2.50/24", "/usr/sbin/arping", 3).is_ok()
        );
    }

    #[test]
    fn rejects_invalid_prefix() {
        assert!(
            LinuxNetworkConfig::new(
                "eth0",
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                33,
                "/usr/sbin/arping",
                3
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_ipv6() {
        assert!(
            LinuxNetworkConfig::new("eth0", "::1".parse().unwrap(), 64, "/usr/sbin/arping", 3)
                .is_err()
        );
    }

    #[test]
    fn rejects_invalid_interface() {
        assert!(
            LinuxNetworkConfig::new(
                " ",
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8,
                "/usr/sbin/arping",
                3
            )
            .is_err()
        );
        assert!(
            LinuxNetworkConfig::new(
                "a\0b",
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                8,
                "/usr/sbin/arping",
                3
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_relative_arping_path() {
        assert!(
            LinuxNetworkConfig::new("eth0", IpAddr::V4(Ipv4Addr::LOCALHOST), 8, "arping", 3)
                .is_err()
        );
    }

    #[test]
    fn exact_vip_observation_is_present() {
        let desired = config();
        let address = [KernelAddress::Valid {
            interface_index: 7,
            address: desired.vip,
            prefix_len: desired.prefix_len,
        }];
        assert_eq!(
            classify_observation(Ok(7), Ok(&address), &desired),
            RawVipObservation::Present
        );
    }

    #[test]
    fn inspected_interface_without_vip_is_absent() {
        let desired = config();
        let address = [KernelAddress::Valid {
            interface_index: 7,
            address: Ipv4Addr::new(192, 0, 2, 51),
            prefix_len: desired.prefix_len,
        }];
        assert_eq!(
            classify_observation(Ok(7), Ok(&address), &desired),
            RawVipObservation::Absent
        );
    }

    #[test]
    fn interface_lookup_failure_is_unknown() {
        let desired = config();
        assert_eq!(
            classify_observation(Err(()), Ok(&[]), &desired),
            RawVipObservation::Unavailable
        );
    }

    #[test]
    fn netlink_query_failure_is_unknown() {
        let desired = config();
        assert_eq!(
            classify_observation(Ok(7), Err(()), &desired),
            RawVipObservation::Unavailable
        );
    }

    #[test]
    fn malformed_response_is_unknown() {
        let desired = config();
        let address = [KernelAddress::Malformed];
        assert_eq!(
            classify_observation(Ok(7), Ok(&address), &desired),
            RawVipObservation::Unavailable
        );
    }

    #[test]
    fn local_address_wins_over_peer_address_in_any_attribute_order() {
        let local = Ipv4Addr::new(192, 0, 2, 50);
        let peer = Ipv4Addr::new(192, 0, 2, 51);
        for attributes in [
            vec![
                AddressAttributeKind::LocalIpv4(local),
                AddressAttributeKind::AddressIpv4(peer),
            ],
            vec![
                AddressAttributeKind::AddressIpv4(peer),
                AddressAttributeKind::LocalIpv4(local),
            ],
        ] {
            assert_eq!(
                extract_local_ipv4(&attributes),
                LocalAddressObservation::LocalIpv4(local)
            );
        }
    }

    #[test]
    fn peer_address_does_not_make_configured_vip_present() {
        let desired = config();
        let peer = [KernelAddress::Valid {
            interface_index: 7,
            address: Ipv4Addr::new(192, 0, 2, 51),
            prefix_len: desired.prefix_len,
        }];
        assert_eq!(
            classify_observation(Ok(7), Ok(&peer), &desired),
            RawVipObservation::Absent
        );
        assert_eq!(
            extract_local_ipv4(&[
                AddressAttributeKind::LocalIpv4(desired.vip),
                AddressAttributeKind::AddressIpv4(Ipv4Addr::new(192, 0, 2, 51)),
            ]),
            LocalAddressObservation::LocalIpv4(desired.vip)
        );
    }

    #[test]
    fn address_only_ipv4_is_supported_as_unambiguous_local_form() {
        let address = Ipv4Addr::new(192, 0, 2, 50);
        assert_eq!(
            extract_local_ipv4(&[AddressAttributeKind::AddressIpv4(address)]),
            LocalAddressObservation::LocalIpv4(address)
        );
    }

    #[test]
    fn ipv6_attributes_are_not_ipv4_local_identity() {
        assert_eq!(
            extract_local_ipv4(&[
                AddressAttributeKind::LocalIpv6,
                AddressAttributeKind::AddressIpv6,
            ]),
            LocalAddressObservation::NonIpv4OrIrrelevant
        );
    }

    #[test]
    fn conflicting_local_attributes_are_unknown() {
        assert_eq!(
            extract_local_ipv4(&[
                AddressAttributeKind::LocalIpv4(Ipv4Addr::new(192, 0, 2, 50)),
                AddressAttributeKind::LocalIpv4(Ipv4Addr::new(192, 0, 2, 51)),
            ]),
            LocalAddressObservation::MalformedOrAmbiguous
        );
    }

    #[test]
    fn unrelated_malformed_entry_does_not_poison_clean_observation() {
        let desired = config();
        let records = [
            (8, KernelAddress::Malformed),
            (
                7,
                KernelAddress::Valid {
                    interface_index: 7,
                    address: Ipv4Addr::new(192, 0, 2, 51),
                    prefix_len: desired.prefix_len,
                },
            ),
        ];
        let clean = filter_kernel_addresses_for_interface(7, &records);
        assert_eq!(
            classify_observation(Ok(7), Ok(&clean), &desired),
            RawVipObservation::Absent
        );
    }

    #[test]
    fn unrelated_malformed_entry_does_not_hide_exact_vip() {
        let desired = config();
        let records = [
            (8, KernelAddress::Malformed),
            (
                7,
                KernelAddress::Valid {
                    interface_index: 7,
                    address: desired.vip,
                    prefix_len: desired.prefix_len,
                },
            ),
        ];
        let relevant = filter_kernel_addresses_for_interface(7, &records);
        assert_eq!(
            classify_observation(Ok(7), Ok(&relevant), &desired),
            RawVipObservation::Present
        );
    }

    #[test]
    fn configured_malformed_entry_remains_unknown() {
        let desired = config();
        let records = [(7, KernelAddress::Malformed)];
        let relevant = filter_kernel_addresses_for_interface(7, &records);
        assert_eq!(
            classify_observation(Ok(7), Ok(&relevant), &desired),
            RawVipObservation::Unavailable
        );
    }

    #[test]
    fn prefix_and_interface_are_part_of_vip_identity() {
        let desired = config();
        let wrong_prefix = [KernelAddress::Valid {
            interface_index: 7,
            address: desired.vip,
            prefix_len: 25,
        }];
        let wrong_interface = [KernelAddress::Valid {
            interface_index: 8,
            address: desired.vip,
            prefix_len: desired.prefix_len,
        }];
        assert_eq!(
            classify_observation(Ok(7), Ok(&wrong_prefix), &desired),
            RawVipObservation::Absent
        );
        assert_eq!(
            classify_observation(Ok(7), Ok(&wrong_interface), &desired),
            RawVipObservation::Absent
        );
    }

    #[test]
    fn arping_arguments_are_exact_and_do_not_use_a_shell() {
        assert_eq!(
            arping_arguments(&config()).as_strings(),
            ["-U", "-I", "eth0", "-c", "3", "192.0.2.50"]
        );
    }

    #[test]
    fn arping_result_mapping_is_conservative() {
        assert_eq!(
            map_arping_result(ArpingProcessResult::ExitZero),
            (ActionDiagnostic::Success, RawGarpOutcome::Succeeded)
        );
        for result in [
            ArpingProcessResult::ExitNonZero,
            ArpingProcessResult::Signaled,
            ArpingProcessResult::TimedOutCleaned,
            ArpingProcessResult::TimedOutReapedAfterKillFailure,
            ArpingProcessResult::WaitFailedCleaned,
            ArpingProcessResult::CleanupFailed,
            ArpingProcessResult::SpawnFailed,
        ] {
            assert_eq!(map_arping_result(result).1, RawGarpOutcome::Failed);
        }
        assert_eq!(
            map_arping_result(ArpingProcessResult::TimedOutCleaned).0,
            ActionDiagnostic::Timeout
        );
        assert_eq!(
            map_arping_result(ArpingProcessResult::Signaled).0,
            ActionDiagnostic::Interrupted
        );
    }

    #[test]
    fn action_result_does_not_fabricate_observation() {
        let desired = config();
        let no_vip = [KernelAddress::Valid {
            interface_index: 7,
            address: Ipv4Addr::new(192, 0, 2, 51),
            prefix_len: desired.prefix_len,
        }];
        assert_eq!(
            classify_observation(Ok(7), Ok(&no_vip), &desired),
            RawVipObservation::Absent
        );
        assert_eq!(
            classify_observation(Ok(7), Ok(&[]), &desired),
            RawVipObservation::Absent
        );
    }

    #[test]
    fn release_observation_can_confirm_absent_after_action_error() {
        let desired = config();
        assert_eq!(
            classify_observation(Ok(7), Ok(&[]), &desired),
            RawVipObservation::Absent
        );
    }

    #[test]
    fn no_automatic_retry_is_encoded_by_one_process_result() {
        assert_eq!(
            map_arping_result(ArpingProcessResult::ExitNonZero).1,
            RawGarpOutcome::Failed
        );
    }

    #[test]
    fn netlink_response_requires_matching_sequence_and_kernel_sender() {
        assert!(valid_netlink_response(7, 7, 0, 0));
        assert!(!valid_netlink_response(7, 8, 0, 0));
        assert!(!valid_netlink_response(7, 7, 42, 0));
        assert!(!valid_netlink_response(7, 7, 0, 1));
    }

    #[test]
    fn cleanup_result_distinguishes_containment_uncertainty() {
        assert_eq!(
            classify_cleanup_result(true, true, true),
            ArpingProcessResult::TimedOutCleaned
        );
        assert_eq!(
            classify_cleanup_result(true, false, true),
            ArpingProcessResult::TimedOutReapedAfterKillFailure
        );
        assert_eq!(
            classify_cleanup_result(false, true, true),
            ArpingProcessResult::WaitFailedCleaned
        );
        assert_eq!(
            classify_cleanup_result(true, true, false),
            ArpingProcessResult::CleanupFailed
        );
        assert_eq!(
            classify_cleanup_result(true, false, false),
            ArpingProcessResult::CleanupFailed
        );
    }
}
