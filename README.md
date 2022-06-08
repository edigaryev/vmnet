# vmnet

Apple's [`vmnet.framework`](https://developer.apple.com/documentation/vmnet) bindings for Rust.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
vmnet = "0.1.0"
```

## Usage

Ensure that your software either has an `com.apple.vm.networking` entitlement or is running with elevated privileges.

Start a NAT interface and receive some packets destined to it:

```rust
fn main() {
    let shared_mode = Shared {
        subnet_options: None,
        ..Default::default()
    };

    let mut iface = Interface::new(Mode::Shared(shared_mode), Options::default()).unwrap();

    let (tx, rx) = sync::mpsc::sync_channel(0);

    iface.set_event_callback(Events::PACKETS_AVAILABLE, move |events, params| {
        if let Some(Parameter::EstimatedPacketsAvailable(pkts)) = params.get(ParameterKind::EstimatedPacketsAvailable) {
            tx.send(pkts);
        }
    }).unwrap();

    let pkts = rx.recv().unwrap();
    println!("receiving {} packets...", pkts);
    for _ in 0..pkts {
        let mut buf: [u8; 1514] = [0; 1514];
        println!("{:?}", iface.read(&mut buf));
    }

    drop(rx);
    iface.finalize().unwrap();
}
```

## Quirks and missing functionality

* due to Apple's usage of [blocks](https://en.wikipedia.org/wiki/Blocks_(C_language_extension)) as a way to retrieve API call results, some methods like `set_event_callback()` require the provided closure to have a `'static` lifetime
  * this manifests itself in not being able to use `Interface` from such closure
  * however, this can be easily worked around by using [interior mutability pattern](https://doc.rust-lang.org/book/ch15-05-interior-mutability.html) or simply by using the callback as a signal carrier
* no [port forwarding](https://developer.apple.com/documentation/vmnet/vmnet_functions) support
* [`vmnet_copy_shared_interface_list()`](https://developer.apple.com/documentation/vmnet/3152677-vmnet_copy_shared_interface_list) is not yet implemented
* due to `API_AVAILABLE` macro not being supported it is assumed that this package is running on macOS 11.0 or newer
