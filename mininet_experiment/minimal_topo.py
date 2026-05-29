"""Minimal Mininet topology for the A/B LDoS experiment.

Topology:

    h1 ---- s1 ---- s2 ---- h2
    h3 ---- s1
    h4 ---- s1

The s1-s2 link is the bottleneck.
"""

from __future__ import annotations


try:
    from mininet.topo import Topo
except ImportError as exc:  # pragma: no cover - exercised on non-Mininet hosts.
    raise SystemExit(
        "Mininet is not installed. Run this experiment on WSL2/Ubuntu after "
        "`bash scripts/setup_wsl_ubuntu_mininet.sh`."
    ) from exc


class MinimalABTopo(Topo):
    """Two-switch topology with one TCP sender, one receiver, and two UDP generators."""

    def build(self) -> None:
        """Create hosts, switches, and constrained links."""
        h1 = self.addHost("h1", ip="10.0.0.1/8")
        h2 = self.addHost("h2", ip="10.0.0.2/8")
        h3 = self.addHost("h3", ip="10.0.0.3/8")
        h4 = self.addHost("h4", ip="10.0.0.4/8")
        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")

        self.addLink(h1, s1, bw=100, delay="10ms")
        self.addLink(h3, s1, bw=100, delay="10ms")
        self.addLink(h4, s1, bw=100, delay="10ms")
        self.addLink(s1, s2, bw=15, delay="20ms")
        self.addLink(s2, h2, bw=100, delay="10ms")


topos = {"minimal_ab_topo": MinimalABTopo}


if __name__ == "__main__":
    from mininet.cli import CLI
    from mininet.link import TCLink
    from mininet.net import Mininet

    network = Mininet(topo=MinimalABTopo(), link=TCLink, autoSetMacs=True)
    try:
        network.start()
        CLI(network)
    finally:
        network.stop()
