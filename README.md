# Realtime Network Visualizer

A tool for discovering and, eventually, visualizing the devices on your local network in real time. The discovery layer is working today: `arpsweep.py` broadcasts an ARP request across your subnet with [Scapy](https://scapy.net/) and reports the IP address, MAC address, hostname (via reverse DNS) and hardware vendor (looked up from the MAC's OUI prefix) of every device that answers. The `Device` dataclass and `arp_sweep()` function are designed to be imported, so a live topology view can build on them.

**Status:** early development. Discovery and tests are done; the live web UI is next.

## Setup

Requires Python 3.10+ and, on Windows, [Npcap](https://npcap.com/).

```bash
git clone https://github.com/zagog629/Realtime-Network-Visualizer.git
cd Realtime-Network-Visualizer

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python3 arpsweep.py --update-oui   # one-time: download the IEEE vendor list
```

## Usage

```bash
sudo .venv/bin/python arpsweep.py                    # auto-detect your subnet
sudo .venv/bin/python arpsweep.py -t 192.168.1.0/24  # scan a specific range
sudo .venv/bin/python arpsweep.py --json             # machine-readable output
```

Example output (illustrative):

```
IP             MAC                HOSTNAME     VENDOR
-------------  -----------------  -----------  ----------------------------
192.168.1.1    28:6f:b9:aa:bb:cc  router.lan   Nokia Shanghai Bell Co. Ltd.
192.168.1.23   b8:27:eb:12:34:56  -            Raspberry Pi Foundation
192.168.1.41   da:a1:19:00:00:01  -            (randomized MAC)

3 device(s) found
```

### Why `sudo`?

Sending ARP requests means crafting raw Ethernet frames, which needs elevated privileges (root on Linux/macOS, an Administrator terminal on Windows). Plain `sudo python3` uses the system Python and won't see the packages in your virtual environment, so point `sudo` at the venv's interpreter as shown above. The `--update-oui` step doesn't need `sudo`.

Only scan networks you own or have permission to test.

## Tests

The tests mock Scapy's network calls, so they need neither root nor a network.

```bash
pip install -r requirements-dev.txt
pytest
```

## Known limitations

- **Vendor coverage:** the downloaded IEEE `oui.csv` only covers 24-bit (MA-L) assignments. Some vendors hold 28- or 36-bit blocks that live in separate IEEE registries, so a few devices will show no vendor.
- **Randomized MACs:** phones and modern operating systems often use private, locally administered MAC addresses. No vendor can be derived from these, so they're labeled `(randomized MAC)`.
- **Hostnames:** reverse DNS is used, and many home routers don't publish names for their clients, so the hostname column is often empty.
- **Missed replies:** ARP replies can be dropped (sleeping phones especially), so a single sweep may miss devices that are actually online.
- **WSL2:** with the default NAT networking, a sweep only sees WSL's virtual subnet. Use [mirrored networking](https://learn.microsoft.com/windows/wsl/networking) or run natively on Windows to scan your real LAN.
- **IPv4 only:** ARP is IPv4-specific; IPv6 devices are found through Neighbor Discovery, which isn't implemented.

## License

See [LICENSE](LICENSE).