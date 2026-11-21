//! Runtime tests: real authenticated TCP links on loopback, real drivers, fake fence device
//! and fake resources sharing one checked world.

use super::*;
use crate::config::Config;
use crate::two_node::controller::ControllerConfig;
use crate::two_node::store::{FileStore, OwnershipState};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::channel;

#[derive(Default)]
struct FakeWorld {
    vip: [bool; 2],
    service: [bool; 2],
    powered: [bool; 2],
    violations: Vec<String>,
    fence_works: bool,
    /// The service's health per node (observed only while it runs).
    healthy: [bool; 2],
    /// A restart makes the service healthy again.
    restart_heals: bool,
    restarts: [u32; 2],
}

type World = Arc<Mutex<FakeWorld>>;

struct FakeOps {
    me: usize,
    world: World,
}

impl ResourceOps for FakeOps {
    fn acquire(&mut self) -> AcquireResult {
        let mut w = self.world.lock().unwrap();
        let other = 1 - self.me;
        if w.vip[other] || w.service[other] {
            let text = format!(
                "node {} acquired while node {other} holds resources",
                self.me
            );
            w.violations.push(text);
        }
        w.vip[self.me] = true;
        w.service[self.me] = true;
        AcquireResult::Acquired
    }
    fn release(&mut self) -> bool {
        let mut w = self.world.lock().unwrap();
        w.vip[self.me] = false;
        w.service[self.me] = false;
        true
    }
    fn observe_health(&mut self) -> Option<bool> {
        let w = self.world.lock().unwrap();
        Some(w.service[self.me] && w.healthy[self.me])
    }
    fn restart(&mut self) -> RestartOutcome {
        let mut w = self.world.lock().unwrap();
        w.restarts[self.me] += 1;
        if w.restart_heals {
            w.healthy[self.me] = true;
            RestartOutcome::Restarted
        } else {
            RestartOutcome::StartFailed("app (still unhealthy)".into())
        }
    }
}

struct FakeFence {
    target: usize,
    world: World,
    stop_target: Arc<AtomicBool>,
}

impl FenceRunner for FakeFence {
    fn fence(&mut self, _: u64, _: u32, _: &str) -> FenceAction {
        let mut w = self.world.lock().unwrap();
        if !w.fence_works {
            return FenceAction::ReportedFailure;
        }
        // Power off: the OS stops, its resources vanish, its process ends.
        w.powered[self.target] = false;
        w.vip[self.target] = false;
        w.service[self.target] = false;
        self.stop_target.store(true, Ordering::SeqCst);
        FenceAction::ReportedSuccess
    }
    fn verify(&mut self, _: u64, _: u32, _: &str) -> Verdict {
        if self.world.lock().unwrap().powered[self.target] {
            Verdict::NotIsolated
        } else {
            Verdict::Isolated
        }
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn toml(node: &str, peer: &str, ports: [u16; 2], fencing: bool) -> String {
    let inbound = node > peer;
    let mut links = String::new();
    for (index, port) in ports.iter().enumerate() {
        let endpoint = if inbound {
            format!("listen = \"127.0.0.1:{port}\"")
        } else {
            format!("peer_address = \"127.0.0.1:{port}\"")
        };
        let role = if index == 0 { "ha" } else { "service" };
        links.push_str(&format!(
            "[[two_node.link]]\nsegment = \"seg{index}\"\nrole = \"{role}\"\ninterface = \"lo{index}\"\n{endpoint}\n"
        ));
    }
    let fencing_section = if fencing {
        "[fencing]\nbackend = \"command\"\nfence = [\"/usr/bin/true\"]\nverify = [\"/usr/bin/true\"]\n"
    } else {
        ""
    };
    let device = if fencing {
        "fencing_device = \"independent\"\nfencing_path = \"separate\"\n"
    } else {
        ""
    };
    format!(
        "[cluster]\nid = \"rt\"\ntopology = \"two-node\"\n[node]\nid = \"{node}\"\npreferred = {}\n[peer]\nid = \"{peer}\"\n[two_node]\n{device}{links}[vip]\naddress = \"192.0.2.10/24\"\ninterface = \"eth0\"\n[service]\nmanager = \"systemd\"\nunit = \"x.service\"\n[health]\ncommand = [\"/usr/bin/true\"]\n[security]\npsk_file = \"/etc/mikagami/cluster.psk\"\n[failover]\nbootstrap_dwell_sec = 1\nbootstrap_defer_sec = 1\ndwell_sec = 2\n{fencing_section}",
        node == "node-a"
    )
}

struct Running {
    stop: Arc<AtomicBool>,
    shared: Arc<LinkShared>,
    threads: Vec<std::thread::JoinHandle<()>>,
    driver: Option<std::thread::JoinHandle<()>>,
    status: Arc<Mutex<Option<StatusView>>>,
}

impl Running {
    fn halt(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(driver) = self.driver.take() {
            driver.join().unwrap();
        }
        for thread in self.threads.drain(..) {
            thread.join().unwrap();
        }
    }

    fn role(&self) -> Option<String> {
        self.status.lock().unwrap().as_ref().map(|s| s.role.clone())
    }
}

fn spawn(
    me: usize,
    config_text: &str,
    psk_byte: u8,
    world: &World,
    stop_self: Arc<AtomicBool>,
    stop_peer: Arc<AtomicBool>,
    dir: &Path,
) -> Running {
    spawn_with(
        me,
        config_text,
        None,
        psk_byte,
        world,
        stop_self,
        stop_peer,
        dir,
    )
}

/// `summary`: the configuration summary to send and require (a shared configuration).
#[allow(clippy::too_many_arguments)]
fn spawn_with(
    me: usize,
    config_text: &str,
    summary: Option<&str>,
    psk_byte: u8,
    world: &World,
    stop_self: Arc<AtomicBool>,
    stop_peer: Arc<AtomicBool>,
    dir: &Path,
) -> Running {
    let config = Config::parse_str(config_text).expect("test config");
    let mut two_node = config.two_node.clone().unwrap();
    two_node.config_summary = summary.map(String::from);
    let mut controller_config = ControllerConfig::from_config(&config).unwrap();
    controller_config.min_uptime_ms = 1_000;
    let state = dir.join(format!("state-{me}.json"));
    let store = FileStore::new(&state);
    if store.load("rt", &config.node.id).is_err() {
        store.init("rt", &config.node.id, false, 0).unwrap();
    }
    let loaded = store.load("rt", &config.node.id);
    let shared = LinkShared::new(two_node.links.len());
    let (sender, receiver) = channel();
    let incarnation = crate::node_mutation::generate_uuid().unwrap();
    let psk = Psk::from_test_bytes([psk_byte; 32]);
    let threads = spawn_links(
        &LinkIdentity {
            cluster: "rt".into(),
            local: config.node.id.clone(),
            peer: config.peer.id.clone(),
            incarnation: incarnation.clone(),
            config: two_node.config_summary.clone(),
        },
        &two_node.links,
        &psk,
        &shared,
        &sender,
    );
    drop(sender);
    let common = Common {
        controller_config,
        incarnation,
        loaded,
        store: Box::new(FileStore::new(&state)),
        shared: Arc::clone(&shared),
        inbound: receiver,
        links: two_node.links.clone(),
        status_path: Some(dir.join(format!("status-{me}.json"))),
        operator_dir: Some(dir.join(format!("operator-{me}"))),
        guard: Box::new(|| Ok(())),
        config_summary: two_node.config_summary.clone(),
        // The production default: the Active is always monitored (warn included).
        health: Some(HealthPolicy::from_config(&config)),
    };
    let parts = common.into_parts(
        FakeFence {
            target: 1 - me,
            world: Arc::clone(world),
            stop_target: stop_peer,
        },
        FakeOps {
            me,
            world: Arc::clone(world),
        },
    );
    let status = Arc::new(Mutex::new(None));
    let status_out = Arc::clone(&status);
    let stop = Arc::clone(&stop_self);
    let driver = std::thread::spawn(move || {
        let mut driver = Driver::start(parts);
        while !stop.load(Ordering::SeqCst) && !driver.exited {
            driver.step(false, false);
            *status_out.lock().unwrap() = Some(driver.status());
        }
    });
    Running {
        stop: stop_self,
        shared,
        threads,
        driver: Some(driver),
        status,
    }
}

fn wait_for(seconds: u64, check: impl Fn() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < end {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    check()
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mkg-two-node-rt-{tag}-{}",
        crate::node_mutation::generate_uuid().unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn loopback_two_links_cold_start_then_fenced_takeover() {
    let dir = temp_dir("e2e");
    let ports = [free_port(), free_port()];
    let world: World = Arc::new(Mutex::new(FakeWorld {
        powered: [true, true],
        fence_works: true,
        ..FakeWorld::default()
    }));
    let stop_a = Arc::new(AtomicBool::new(false));
    let stop_b = Arc::new(AtomicBool::new(false));
    let mut a = spawn(
        0,
        &toml("node-a", "node-b", ports, true),
        7,
        &world,
        Arc::clone(&stop_a),
        Arc::clone(&stop_b),
        &dir,
    );
    let mut b = spawn(
        1,
        &toml("node-b", "node-a", ports, true),
        7,
        &world,
        Arc::clone(&stop_b),
        Arc::clone(&stop_a),
        &dir,
    );
    assert!(
        wait_for(20, || a.role().as_deref() == Some("active")),
        "cold start: node-a Active ({:?} / {:?})",
        a.role(),
        b.role()
    );
    assert!(wait_for(10, || b
        .status
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|s| s.links.iter().all(|l| l.up) && s.epoch == 1)));
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(b.role().as_deref(), Some("standby"));
    {
        let w = world.lock().unwrap();
        assert_eq!((w.vip, w.service), ([true, false], [true, false]));
    }
    // node-a hangs (process and OS stop answering, resources stay until fenced).
    a.stop.store(true, Ordering::SeqCst);
    a.shared.stop.store(true, Ordering::SeqCst);
    assert!(
        wait_for(30, || b.role().as_deref() == Some("active")),
        "takeover after a confirmed fence ({:?})",
        b.role()
    );
    {
        let w = world.lock().unwrap();
        assert!(w.violations.is_empty(), "{:?}", w.violations);
        assert_eq!((w.vip, w.service), ([false, true], [false, true]));
        assert!(!w.powered[0]);
    }
    let durable = FileStore::new(dir.join("state-1.json"))
        .load("rt", "node-b")
        .unwrap();
    assert_eq!(durable.epoch, 2);
    assert!(matches!(
        durable.intent.unwrap().basis,
        crate::two_node::store::Basis::Fence { .. }
    ));
    let status: StatusView =
        serde_json::from_slice(&std::fs::read(dir.join("status-1.json")).unwrap()).unwrap();
    assert_eq!(status.role, "active");
    a.halt();
    b.halt();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_peer_with_the_wrong_key_never_connects_and_nothing_promotes() {
    let dir = temp_dir("psk");
    let ports = [free_port(), free_port()];
    let world: World = Arc::new(Mutex::new(FakeWorld {
        powered: [true, true],
        fence_works: true,
        ..FakeWorld::default()
    }));
    let stop_a = Arc::new(AtomicBool::new(false));
    let stop_b = Arc::new(AtomicBool::new(false));
    let mut a = spawn(
        0,
        &toml("node-a", "node-b", ports, false),
        1,
        &world,
        Arc::clone(&stop_a),
        Arc::clone(&stop_b),
        &dir,
    );
    let mut b = spawn(
        1,
        &toml("node-b", "node-a", ports, false),
        2,
        &world,
        Arc::clone(&stop_b),
        Arc::clone(&stop_a),
        &dir,
    );
    std::thread::sleep(Duration::from_secs(8));
    for running in [&a, &b] {
        let status = running.status.lock().unwrap().clone().unwrap();
        assert_eq!(status.role, "standby");
        assert!(status.links.iter().all(|l| !l.up));
        assert!(!status.peer_connected);
    }
    assert_eq!(world.lock().unwrap().vip, [false, false]);
    a.halt();
    b.halt();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn operator_requests_are_taken_once_and_checked() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("op");
    let good = OperatorRequest {
        version: 1,
        cluster: "rt".into(),
        target: "node-b".into(),
        kind: OperatorKind::AttestPeerStopped,
        attestation_id: "6f1c3b8e-2d4a-4c5b-9e7f-0a1b2c3d4e5f".into(),
    };
    std::fs::write(dir.join("1.json"), serde_json::to_vec(&good).unwrap()).unwrap();
    std::fs::set_permissions(dir.join("1.json"), std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut wrong_cluster = good.clone();
    wrong_cluster.cluster = "other".into();
    std::fs::write(
        dir.join("2.json"),
        serde_json::to_vec(&wrong_cluster).unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(dir.join("2.json"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(dir.join("3.json"), serde_json::to_vec(&good).unwrap()).unwrap();
    std::fs::set_permissions(dir.join("3.json"), std::fs::Permissions::from_mode(0o666)).unwrap();
    std::fs::write(dir.join("4.json"), b"{not json").unwrap();
    std::os::unix::fs::symlink(dir.join("1.json"), dir.join("5.json")).unwrap();
    let (requests, problems) = take_operator_requests(&dir, "rt");
    assert_eq!(requests, vec![good]);
    assert_eq!(problems.len(), 4, "{problems:?}");
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "every file is consumed"
    );
    let (again, _) = take_operator_requests(&dir, "rt");
    assert!(again.is_empty());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_lost_control_lock_stops_protected_effects() {
    let dir = temp_dir("guard");
    let config =
        Config::parse_str(&toml("node-a", "node-b", [free_port(), free_port()], false)).unwrap();
    let two_node = config.two_node.clone().unwrap();
    let world: World = Arc::new(Mutex::new(FakeWorld::default()));
    let (_sender, receiver) = channel();
    let store = FileStore::new(dir.join("s.json"));
    store.init("rt", "node-a", false, 0).unwrap();
    let common = Common {
        controller_config: ControllerConfig::from_config(&config).unwrap(),
        incarnation: "i".into(),
        loaded: Ok(OwnershipState::fresh("rt", "node-a")),
        store: Box::new(FileStore::new(dir.join("s.json"))),
        shared: LinkShared::new(two_node.links.len()),
        inbound: receiver,
        links: two_node.links,
        status_path: None,
        operator_dir: None,
        guard: Box::new(|| Err("replaced".into())),
        config_summary: None,
        health: None,
    };
    let driver = Driver::start(common.into_parts(
        NoFence,
        FakeOps {
            me: 0,
            world: Arc::clone(&world),
        },
    ));
    assert!(driver.failed);
    assert_eq!(
        driver.controller.role(),
        crate::two_node::wire::Role::Blocked
    );
    std::fs::remove_dir_all(dir).unwrap();
}

// ---- LA-01 (run 2n-20261118b): where a production acquisition stops ------------------------

mod acquire_steps {
    use crate::resource_executor::{
        ActionDiagnostic, NetworkBackend, RawGarpOutcome, RawHealthObservation,
        RawServiceObservation, RawVipObservation, ResourceExecutor, ServiceBackend, sealed,
    };
    use crate::two_node::controller::AcquireResult;
    use crate::two_node::runtime::{ExecutorOps, ResourceOps};

    struct Net {
        vip: bool,
        add_works: bool,
        garp: RawGarpOutcome,
    }
    impl sealed::NetworkBackend for Net {}
    impl NetworkBackend for Net {
        fn request_vip_acquire(&mut self) -> ActionDiagnostic {
            self.vip = self.add_works;
            ActionDiagnostic::Success
        }
        fn observe_vip(&mut self) -> RawVipObservation {
            if self.vip {
                RawVipObservation::Present
            } else {
                RawVipObservation::Absent
            }
        }
        fn request_vip_release(&mut self) -> ActionDiagnostic {
            self.vip = false;
            ActionDiagnostic::Success
        }
        fn send_garp(&mut self) -> (ActionDiagnostic, RawGarpOutcome) {
            (ActionDiagnostic::Success, self.garp)
        }
    }

    /// A systemd unit: `ready_on_start` is a service whose start returns once it answers;
    /// otherwise (Type=simple python http.server) it answers only from the second probe.
    struct Svc {
        running: bool,
        ready_on_start: bool,
        probes: u32,
    }
    impl sealed::ServiceBackend for Svc {}
    impl ServiceBackend for Svc {
        fn request_service_start(&mut self) -> ActionDiagnostic {
            self.running = true;
            self.probes = 0;
            ActionDiagnostic::Success
        }
        fn observe_service(&mut self) -> RawServiceObservation {
            if self.running {
                RawServiceObservation::Running
            } else {
                RawServiceObservation::Stopped
            }
        }
        fn request_service_stop(&mut self) -> ActionDiagnostic {
            self.running = false;
            ActionDiagnostic::Success
        }
        fn observe_health(&mut self) -> RawHealthObservation {
            self.probes += 1;
            if self.running && (self.ready_on_start || self.probes > 1) {
                RawHealthObservation::Healthy
            } else {
                RawHealthObservation::Unhealthy
            }
        }
    }

    fn ops(ready: bool, add_works: bool, garp: RawGarpOutcome) -> ExecutorOps<Net, Svc> {
        ExecutorOps::new(ResourceExecutor::new(
            Net {
                vip: false,
                add_works,
                garp,
            },
            Svc {
                running: false,
                ready_on_start: ready,
                probes: 0,
            },
        ))
    }

    #[test]
    fn a_single_service_restart_keeps_the_vip_and_checks_health() {
        use crate::two_node::runtime::RestartOutcome;
        let mut o = ops(true, true, RawGarpOutcome::Succeeded);
        assert_eq!(o.acquire(), AcquireResult::Acquired);
        assert_eq!(o.restart(), RestartOutcome::Restarted);
        assert_eq!(o.observe_health(), Some(true));
        // Not ready on its first probe: the restart reports a failure (released by the caller).
        let mut slow = ops(false, true, RawGarpOutcome::Succeeded);
        assert!(slow.acquire_steps().is_err());
        assert!(matches!(slow.restart(), RestartOutcome::StartFailed(_)));
    }

    #[test]
    fn a_service_not_answering_when_its_start_returns_fails_at_the_health_step_and_rolls_back() {
        let mut o = ops(false, true, RawGarpOutcome::Succeeded);
        let step = o.acquire_steps().unwrap_err();
        assert!(
            step.starts_with("health check right after the service start"),
            "{step}"
        );
        assert_eq!(
            o.acquire(),
            AcquireResult::Failed,
            "every attempt fails the same way"
        );
        assert!(
            o.release(),
            "service stopped and VIP absent after the failure"
        );
    }

    #[test]
    fn a_service_ready_when_its_start_returns_is_acquired() {
        let mut o = ops(true, true, RawGarpOutcome::Succeeded);
        assert_eq!(o.acquire(), AcquireResult::Acquired);
        assert!(o.release());
    }

    #[test]
    fn the_vip_and_garp_steps_are_named_too() {
        let step = ops(true, false, RawGarpOutcome::Succeeded)
            .acquire_steps()
            .unwrap_err();
        assert!(step.starts_with("vip (observed"), "{step}");
        let mut o = ops(true, true, RawGarpOutcome::Failed);
        let step = o.acquire_steps().unwrap_err();
        assert!(step.starts_with("gratuitous ARP"), "{step}");
        assert!(o.release());
    }
}

#[test]
fn loopback_config_mismatch_is_refused_and_never_taken_for_a_loss() {
    let dir = temp_dir("mismatch");
    let ports = [free_port(), free_port()];
    let world: World = Arc::new(Mutex::new(FakeWorld {
        powered: [true, true],
        fence_works: true,
        ..FakeWorld::default()
    }));
    let stop_a = Arc::new(AtomicBool::new(false));
    let stop_b = Arc::new(AtomicBool::new(false));
    // Cold start with the same summary: node-a becomes Active.
    let mut a = spawn_with(
        0,
        &toml("node-a", "node-b", ports, true),
        Some("cluster=1,vip=1"),
        7,
        &world,
        Arc::clone(&stop_a),
        Arc::clone(&stop_b),
        &dir,
    );
    let mut b = spawn_with(
        1,
        &toml("node-b", "node-a", ports, true),
        Some("cluster=1,vip=1"),
        7,
        &world,
        Arc::clone(&stop_b),
        Arc::clone(&stop_a),
        &dir,
    );
    assert!(
        wait_for(20, || a.role().as_deref() == Some("active")),
        "cold start ({:?} / {:?})",
        a.role(),
        b.role()
    );
    std::thread::sleep(Duration::from_secs(3));
    // node-b restarts with another configuration (its process ends; a new one starts).
    b.halt();
    let stop_b2 = Arc::new(AtomicBool::new(false));
    let mut b2 = spawn_with(
        1,
        &toml("node-b", "node-a", ports, true),
        Some("cluster=1,vip=2"),
        7,
        &world,
        Arc::clone(&stop_b2),
        Arc::clone(&stop_a),
        &dir,
    );
    let mismatch = |r: &Running| {
        r.status
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|s| s.config_mismatch && !s.peer_connected)
    };
    assert!(
        wait_for(15, || mismatch(&a) && mismatch(&b2)),
        "both see the mismatch"
    );
    // Long enough for a loss-founded fence (dwell 2 s, uptime 1 s) to have happened.
    std::thread::sleep(Duration::from_secs(8));
    assert_eq!(a.role().as_deref(), Some("active"));
    assert_eq!(b2.role().as_deref(), Some("standby"));
    {
        let w = world.lock().unwrap();
        assert!(w.violations.is_empty(), "{:?}", w.violations);
        assert_eq!(w.powered, [true, true], "nobody was fenced");
        assert_eq!((w.vip, w.service), ([true, false], [true, false]));
    }
    // The configuration is fixed: node-b restarts with the same summary and is admitted.
    b2.halt();
    let stop_b3 = Arc::new(AtomicBool::new(false));
    let mut b3 = spawn_with(
        1,
        &toml("node-b", "node-a", ports, true),
        Some("cluster=1,vip=1"),
        7,
        &world,
        Arc::clone(&stop_b3),
        Arc::clone(&stop_a),
        &dir,
    );
    assert!(wait_for(20, || b3
        .status
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|s| s.peer_connected && !s.config_mismatch)));
    assert!(wait_for(15, || !a
        .status
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|s| s.config_mismatch)));
    assert_eq!(a.role().as_deref(), Some("active"));
    a.halt();
    b3.halt();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn loopback_a_shared_and_a_per_node_file_do_not_connect() {
    let dir = temp_dir("mixed");
    let ports = [free_port(), free_port()];
    let world: World = Arc::new(Mutex::new(FakeWorld {
        powered: [true, true],
        ..FakeWorld::default()
    }));
    let stop_a = Arc::new(AtomicBool::new(false));
    let stop_b = Arc::new(AtomicBool::new(false));
    let mut a = spawn_with(
        0,
        &toml("node-a", "node-b", ports, false),
        Some("cluster=1"),
        7,
        &world,
        Arc::clone(&stop_a),
        Arc::clone(&stop_b),
        &dir,
    );
    let mut b = spawn(
        1,
        &toml("node-b", "node-a", ports, false),
        7,
        &world,
        Arc::clone(&stop_b),
        Arc::clone(&stop_a),
        &dir,
    );
    let seen = |r: &Running| {
        r.status
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|s| s.config_mismatch)
    };
    assert!(wait_for(15, || seen(&a) && seen(&b)));
    std::thread::sleep(Duration::from_secs(4));
    assert_ne!(a.role().as_deref(), Some("active"));
    assert_ne!(b.role().as_deref(), Some("active"));
    a.halt();
    b.halt();
    std::fs::remove_dir_all(dir).unwrap();
}

mod group_steps {
    use crate::resource_executor::{
        ActionDiagnostic, NetworkBackend, RawGarpOutcome, RawHealthObservation,
        RawServiceObservation, RawVipObservation, ResourceExecutor, ServiceBackend, sealed,
    };
    use crate::two_node::controller::AcquireResult;
    use crate::two_node::runtime::{GroupMember, GroupOps, NoNetwork, ResourceOps};
    use std::sync::{Arc, Mutex};

    /// Every action in order, shared by the VIP and the services.
    type Journal = Arc<Mutex<Vec<String>>>;

    struct Net {
        vip: bool,
        add_works: bool,
        release_works: bool,
        journal: Journal,
    }
    impl sealed::NetworkBackend for Net {}
    impl NetworkBackend for Net {
        fn request_vip_acquire(&mut self) -> ActionDiagnostic {
            self.journal.lock().unwrap().push("vip+".into());
            self.vip = self.add_works;
            ActionDiagnostic::Success
        }
        fn observe_vip(&mut self) -> RawVipObservation {
            if self.vip {
                RawVipObservation::Present
            } else {
                RawVipObservation::Absent
            }
        }
        fn request_vip_release(&mut self) -> ActionDiagnostic {
            self.journal.lock().unwrap().push("vip-".into());
            if self.release_works {
                self.vip = false;
            }
            ActionDiagnostic::Success
        }
        fn send_garp(&mut self) -> (ActionDiagnostic, RawGarpOutcome) {
            self.journal.lock().unwrap().push("garp".into());
            (ActionDiagnostic::Success, RawGarpOutcome::Succeeded)
        }
    }

    struct Svc {
        name: &'static str,
        running: bool,
        start_works: bool,
        stop_works: bool,
        healthy: bool,
        journal: Journal,
    }
    impl sealed::ServiceBackend for Svc {}
    impl ServiceBackend for Svc {
        fn request_service_start(&mut self) -> ActionDiagnostic {
            self.journal.lock().unwrap().push(format!("{}+", self.name));
            self.running = self.start_works;
            ActionDiagnostic::Success
        }
        fn observe_service(&mut self) -> RawServiceObservation {
            if self.running {
                RawServiceObservation::Running
            } else {
                RawServiceObservation::Stopped
            }
        }
        fn request_service_stop(&mut self) -> ActionDiagnostic {
            self.journal.lock().unwrap().push(format!("{}-", self.name));
            if self.stop_works {
                self.running = false;
            }
            ActionDiagnostic::Success
        }
        fn observe_health(&mut self) -> RawHealthObservation {
            self.journal.lock().unwrap().push("health".into());
            if self.healthy {
                RawHealthObservation::Healthy
            } else {
                RawHealthObservation::Unhealthy
            }
        }
    }

    struct Spec {
        vip_at: usize,
        fail_start: Option<&'static str>,
        fail_stop: Option<&'static str>,
        healthy: bool,
        vip_add_works: bool,
    }

    impl Default for Spec {
        fn default() -> Self {
            Self {
                vip_at: 2,
                fail_start: None,
                fail_stop: None,
                healthy: true,
                vip_add_works: true,
            }
        }
    }

    /// db, app and the VIP at `vip_at` (0..=2).
    fn group(spec: &Spec) -> (GroupOps<Net, Svc>, Journal) {
        let journal: Journal = Arc::new(Mutex::new(Vec::new()));
        let service = |name: &'static str| GroupMember::Service {
            name: name.into(),
            executor: ResourceExecutor::new(
                NoNetwork,
                Svc {
                    name,
                    running: false,
                    start_works: spec.fail_start != Some(name),
                    stop_works: spec.fail_stop != Some(name),
                    healthy: spec.healthy,
                    journal: Arc::clone(&journal),
                },
            ),
        };
        let mut members = vec![service("db"), service("app")];
        members.insert(spec.vip_at, GroupMember::Vip { name: "vip".into() });
        let ops = GroupOps::new(
            Net {
                vip: false,
                add_works: spec.vip_add_works,
                release_works: spec.fail_stop != Some("vip"),
                journal: Arc::clone(&journal),
            },
            members,
        );
        (ops, journal)
    }

    fn take(journal: &Journal) -> Vec<String> {
        std::mem::take(&mut *journal.lock().unwrap())
    }

    #[test]
    fn starts_in_order_checks_health_then_announces_and_stops_in_reverse() {
        let (mut ops, journal) = group(&Spec::default());
        assert_eq!(ops.acquire(), AcquireResult::Acquired);
        assert_eq!(take(&journal), ["db+", "app+", "vip+", "health", "garp"]);
        assert_eq!(
            ops.resource_states(),
            [
                ("db".to_string(), "running".to_string()),
                ("app".into(), "running".into()),
                ("vip".into(), "present".into())
            ]
        );
        assert!(ops.release());
        assert_eq!(take(&journal), ["vip-", "app-", "db-"]);
        assert!(
            ops.resource_states()
                .iter()
                .all(|(_, s)| s == "stopped" || s == "absent")
        );
    }

    #[test]
    fn the_vip_position_is_the_configured_one_but_garp_is_always_after_health() {
        let (mut ops, journal) = group(&Spec {
            vip_at: 0,
            ..Spec::default()
        });
        assert_eq!(ops.acquire(), AcquireResult::Acquired);
        assert_eq!(take(&journal), ["vip+", "db+", "app+", "health", "garp"]);
        assert!(ops.release());
        assert_eq!(take(&journal), ["app-", "db-", "vip-"]);
    }

    #[test]
    fn a_failed_start_stops_the_acquisition_at_that_resource() {
        let (mut ops, journal) = group(&Spec {
            fail_start: Some("app"),
            ..Spec::default()
        });
        let step = ops.acquire_steps().unwrap_err();
        assert!(step.starts_with("app (start"), "{step}");
        // Nothing after the failed resource ran: no VIP, no health, no announcement.
        assert_eq!(take(&journal), ["db+", "app+"]);
        // The controller then releases everything in reverse (all confirmed stopped).
        assert!(ops.release());
        assert_eq!(take(&journal), ["vip-", "app-", "db-"]);
    }

    #[test]
    fn an_unhealthy_group_never_announces_the_vip() {
        let (mut ops, journal) = group(&Spec {
            healthy: false,
            ..Spec::default()
        });
        let step = ops.acquire_steps().unwrap_err();
        assert!(
            step.starts_with("health check after every resource started"),
            "{step}"
        );
        let actions = take(&journal);
        assert!(!actions.contains(&"garp".to_string()), "{actions:?}");
        assert!(ops.release());
    }

    #[test]
    fn a_vip_that_does_not_appear_stops_the_acquisition() {
        let (mut ops, journal) = group(&Spec {
            vip_add_works: false,
            ..Spec::default()
        });
        assert!(ops.acquire_steps().unwrap_err().starts_with("vip (vip"));
        assert_eq!(take(&journal), ["db+", "app+", "vip+"]);
    }

    #[test]
    fn an_unconfirmed_stop_keeps_the_resources_before_it_and_is_not_zero_resource() {
        let (mut ops, journal) = group(&Spec {
            fail_stop: Some("app"),
            ..Spec::default()
        });
        assert_eq!(ops.acquire(), AcquireResult::Acquired);
        take(&journal);
        assert!(!ops.release(), "an unconfirmed stop is never zero-resource");
        // The database (started before the app) is not stopped under a running app.
        assert_eq!(take(&journal), ["vip-", "app-"]);
        let states = ops.resource_states();
        assert_eq!(states[1], ("app".into(), "running".into()));
        assert_eq!(states[0], ("db".into(), "running".into()));
        // A VIP that does not go away keeps every service.
        let (mut ops, journal) = group(&Spec {
            fail_stop: Some("vip"),
            ..Spec::default()
        });
        assert_eq!(ops.acquire(), AcquireResult::Acquired);
        take(&journal);
        assert!(!ops.release());
        assert_eq!(take(&journal), ["vip-"]);
    }

    #[test]
    fn a_restart_stops_the_services_in_reverse_keeps_the_vip_and_starts_them_in_order() {
        let (mut ops, journal) = group(&Spec::default());
        assert_eq!(ops.acquire(), AcquireResult::Acquired);
        take(&journal);
        assert_eq!(
            ops.restart(),
            crate::two_node::runtime::RestartOutcome::Restarted
        );
        assert_eq!(take(&journal), ["app-", "db-", "db+", "app+", "health"]);
    }

    #[test]
    fn a_restart_whose_stop_is_not_confirmed_starts_nothing() {
        let (mut ops, journal) = group(&Spec {
            fail_stop: Some("app"),
            ..Spec::default()
        });
        assert_eq!(ops.acquire(), AcquireResult::Acquired);
        take(&journal);
        let outcome = ops.restart();
        assert!(
            matches!(&outcome, crate::two_node::runtime::RestartOutcome::StopUnconfirmed(w) if w.starts_with("app")),
            "{outcome:?}"
        );
        assert_eq!(
            take(&journal),
            ["app-"],
            "db is not stopped under a running app"
        );
    }

    #[test]
    fn a_restart_that_cannot_start_or_stays_unhealthy_is_a_failure() {
        let (mut ops, journal) = group(&Spec {
            healthy: false,
            ..Spec::default()
        });
        // The acquisition itself fails at the health step; a restart reports the same.
        assert!(ops.acquire_steps().is_err());
        take(&journal);
        assert!(matches!(
            ops.restart(),
            crate::two_node::runtime::RestartOutcome::StartFailed(_)
        ));
    }

    #[test]
    fn the_startup_release_of_a_never_started_group_is_zero_resource() {
        let (mut ops, journal) = group(&Spec::default());
        assert!(ops.release());
        assert_eq!(take(&journal), ["vip-", "app-", "db-"]);
    }
}

fn with_on_failure(text: &str, action: &str) -> String {
    text.replace(
        "[health]\ncommand = [\"/usr/bin/true\"]\n",
        &format!(
            "[health]\ncommand = [\"/usr/bin/true\"]\non_failure = \"{action}\"\nfailure_threshold = 2\nsuccess_threshold = 1\n"
        ),
    )
}

fn health_world() -> World {
    Arc::new(Mutex::new(FakeWorld {
        powered: [true, true],
        fence_works: true,
        healthy: [true, true],
        ..FakeWorld::default()
    }))
}

#[test]
fn loopback_health_failover_hands_the_service_over_without_fencing() {
    let dir = temp_dir("health-failover");
    let ports = [free_port(), free_port()];
    let world = health_world();
    let stop_a = Arc::new(AtomicBool::new(false));
    let stop_b = Arc::new(AtomicBool::new(false));
    let mut a = spawn(
        0,
        &with_on_failure(&toml("node-a", "node-b", ports, true), "failover"),
        7,
        &world,
        Arc::clone(&stop_a),
        Arc::clone(&stop_b),
        &dir,
    );
    let mut b = spawn(
        1,
        &with_on_failure(&toml("node-b", "node-a", ports, true), "failover"),
        7,
        &world,
        Arc::clone(&stop_b),
        Arc::clone(&stop_a),
        &dir,
    );
    assert!(wait_for(20, || a.role().as_deref() == Some("active")));
    std::thread::sleep(Duration::from_secs(3));
    world.lock().unwrap().healthy[0] = false;
    assert!(
        wait_for(30, || b.role().as_deref() == Some("active")),
        "health failover ({:?} / {:?})",
        a.role(),
        b.role()
    );
    std::thread::sleep(Duration::from_secs(3));
    {
        let w = world.lock().unwrap();
        assert!(w.violations.is_empty(), "{:?}", w.violations);
        assert_eq!(w.powered, [true, true], "no fencing");
        assert_eq!((w.vip, w.service), ([false, true], [false, true]));
    }
    assert_eq!(a.role().as_deref(), Some("standby"));
    let view = b.status.lock().unwrap().clone().unwrap();
    assert_eq!(view.health.unwrap().state, "healthy");
    a.halt();
    b.halt();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn loopback_health_restart_heals_locally_and_keeps_the_ownership() {
    let dir = temp_dir("health-restart");
    let ports = [free_port(), free_port()];
    let world = health_world();
    world.lock().unwrap().restart_heals = true;
    let stop_a = Arc::new(AtomicBool::new(false));
    let stop_b = Arc::new(AtomicBool::new(false));
    let mut a = spawn(
        0,
        &with_on_failure(&toml("node-a", "node-b", ports, true), "restart"),
        7,
        &world,
        Arc::clone(&stop_a),
        Arc::clone(&stop_b),
        &dir,
    );
    let mut b = spawn(
        1,
        &with_on_failure(&toml("node-b", "node-a", ports, true), "restart"),
        7,
        &world,
        Arc::clone(&stop_b),
        Arc::clone(&stop_a),
        &dir,
    );
    assert!(wait_for(20, || a.role().as_deref() == Some("active")));
    std::thread::sleep(Duration::from_secs(3));
    world.lock().unwrap().healthy[0] = false;
    assert!(wait_for(20, || world.lock().unwrap().restarts[0] == 1));
    std::thread::sleep(Duration::from_secs(6));
    assert_eq!(a.role().as_deref(), Some("active"));
    assert_eq!(b.role().as_deref(), Some("standby"));
    let view = a.status.lock().unwrap().clone().unwrap().health.unwrap();
    assert_eq!(view.last_action.as_deref(), Some("restarted"));
    assert_eq!(view.state, "healthy");
    {
        let w = world.lock().unwrap();
        assert!(w.violations.is_empty(), "{:?}", w.violations);
        assert_eq!(w.restarts, [1, 0]);
    }
    a.halt();
    b.halt();
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn loopback_health_restart_that_fails_releases_and_the_peer_takes_over() {
    let dir = temp_dir("health-restart-fails");
    let ports = [free_port(), free_port()];
    let world = health_world();
    let stop_a = Arc::new(AtomicBool::new(false));
    let stop_b = Arc::new(AtomicBool::new(false));
    let mut a = spawn(
        0,
        &with_on_failure(&toml("node-a", "node-b", ports, true), "restart"),
        7,
        &world,
        Arc::clone(&stop_a),
        Arc::clone(&stop_b),
        &dir,
    );
    let mut b = spawn(
        1,
        &with_on_failure(&toml("node-b", "node-a", ports, true), "restart"),
        7,
        &world,
        Arc::clone(&stop_b),
        Arc::clone(&stop_a),
        &dir,
    );
    assert!(wait_for(20, || a.role().as_deref() == Some("active")));
    std::thread::sleep(Duration::from_secs(3));
    world.lock().unwrap().healthy[0] = false;
    assert!(
        wait_for(40, || b.role().as_deref() == Some("active")),
        "({:?} / {:?})",
        a.role(),
        b.role()
    );
    {
        let w = world.lock().unwrap();
        assert!(w.violations.is_empty(), "{:?}", w.violations);
        assert_eq!(w.powered, [true, true]);
        assert_eq!(w.restarts[0], 1);
    }
    a.halt();
    b.halt();
    std::fs::remove_dir_all(dir).unwrap();
}
