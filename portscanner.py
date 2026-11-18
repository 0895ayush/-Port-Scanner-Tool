"""Educational TCP/UDP port checks for services on this computer only."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import errno
import json
import select
import socket
import sys
import time

LOOPBACK = "127.0.0.1"
DEFAULT_PORTS = "22,53,80,443,8000,8080"
DNS_QUERY = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09localhost\x00\x00\x01\x00\x01"
NTP_QUERY = b"\x1b" + 47 * b"\x00"


def parse_ports(value: str) -> list[int]:
    """Parse comma-separated ports and inclusive ranges."""
    ports: set[int] = set()
    try:
        for part in value.split(","):
            if "-" in part:
                start_text, end_text = part.split("-", maxsplit=1)
                start, end = int(start_text), int(end_text)
                if start > end:
                    raise ValueError
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
    except ValueError as error:
        raise argparse.ArgumentTypeError("use ports like 22,80,8000-8010") from error

    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise argparse.ArgumentTypeError("ports must be between 1 and 65535")
    return sorted(ports)


def scan_tcp_details(port: int, timeout: float, grab_banner: bool = False) -> tuple[str, str]:
    """Check a local TCP port and optionally read its greeting."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setblocking(False)
        result = sock.connect_ex((LOOPBACK, port))
        pending_codes = {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY}
        if result not in (0, errno.EISCONN):
            if result not in pending_codes:
                if result in (errno.ECONNREFUSED, errno.ECONNRESET):
                    return "closed", ""
                if result == errno.ETIMEDOUT:
                    return "filtered", ""
                return "error", ""
            _, writable, exceptional = select.select([], [sock], [sock], timeout)
            if not writable and not exceptional:
                return "filtered", ""
            result = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if result in (errno.ECONNREFUSED, errno.ECONNRESET):
                return "closed", ""
            if result:
                return "error", ""

        if not grab_banner:
            return "open", ""
        sock.settimeout(min(timeout, 0.25))
        try:
            data = sock.recv(256)
        except (socket.timeout, OSError):
            return "open", ""
        banner = data.decode("utf-8", errors="replace")
        banner = " ".join(
            "".join(character if character.isprintable() else " " for character in banner).split()
        )[:120]
        return "open", banner
    except (ConnectionRefusedError, ConnectionResetError):
        return "closed", ""
    except socket.timeout:
        return "filtered", ""
    except OSError:
        return "error", ""
    finally:
        sock.close()


def scan_tcp(port: int, timeout: float, grab_banner: bool = False) -> str:
    """Return the state of a local TCP port."""
    return scan_tcp_details(port, timeout, grab_banner)[0]


def udp_probe(port: int) -> bytes:
    """Build a small request appropriate for common UDP services."""
    if port == 53:
        return DNS_QUERY
    if port == 123:
        return NTP_QUERY
    return b"\x00"


def scan_udp(port: int, timeout: float) -> str:
    """Check a local UDP port using a connected datagram socket."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((LOOPBACK, port))
            sock.send(udp_probe(port))
            sock.recv(1024)
            return "open"
        except (ConnectionRefusedError, ConnectionResetError):
            return "closed"
        except socket.timeout:
            return "open|filtered (no response)"
        except OSError:
            return "error"


def service_name(port: int, protocol: str) -> str:
    """Look up the conventional service name for a port."""
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "unknown"


def display_state(protocol: str, state: str) -> str:
    """Expand UDP's closed state for display."""
    if protocol == "udp" and state == "closed":
        return "closed (ICMP port unreachable)"
    return state


def run_check(protocol: str, port: int, timeout: float, grab_banner: bool) -> tuple[str, str]:
    """Run one protocol check and return its state and banner."""
    if protocol == "tcp":
        return scan_tcp_details(port, timeout, grab_banner)
    return scan_udp(port, timeout), ""


def print_results(results: list[dict[str, object]], show_all: bool) -> None:
    """Print visible results in aligned columns and summarize hidden results."""
    visible_states = {"open", "open|filtered (no response)"}
    shown = [
        result for result in results
        if show_all or result["state"] in visible_states
    ]
    print(f"{'PORT/PROTO':<12} {'STATE':<34} {'SERVICE':<16} BANNER")
    print("-" * 100)
    for result in shown:
        protocol = str(result["protocol"])
        state = display_state(protocol, str(result["state"]))
        banner = str(result["banner"])[:80]
        print(
            f"{str(result['port']) + '/' + protocol:<12} "
            f"{state:<34} {str(result['service']):<16} {banner}"
        )

    hidden_counts: dict[str, int] = {}
    for result in results:
        if result not in shown:
            state = display_state(str(result["protocol"]), str(result["state"]))
            hidden_counts[state] = hidden_counts.get(state, 0) + 1
    for state, count in sorted(hidden_counts.items()):
        print(f"Not shown: {count} {state}")


def main() -> int:
    """Parse options, scan loopback ports, and print or save results."""
    parser = argparse.ArgumentParser(
        description="Check TCP/UDP ports on this computer (127.0.0.1) only."
    )
    parser.add_argument("start_port", nargs="?", type=int, help="first port in the range")
    parser.add_argument("end_port", nargs="?", type=int, help="last port in the range")
    parser.add_argument(
        "--ports", type=parse_ports,
        help="comma-separated ports or ranges (cannot be combined with positional ports)",
    )
    parser.add_argument(
        "--protocol", choices=("tcp", "udp", "both"), default="tcp",
        help="protocol to check (default: tcp)",
    )
    parser.add_argument(
        "--timeout", type=float, default=0.25,
        help="per-port response timeout in seconds (default: 0.25)",
    )
    parser.add_argument(
        "--workers", type=int, default=64,
        help="maximum number of concurrent checks (default: 64; max: 128)",
    )
    parser.add_argument(
        "--banner", action="store_true",
        help="read a short banner passively from open TCP ports",
    )
    parser.add_argument(
        "--show-all", action="store_true", help="also print closed and filtered ports"
    )
    parser.add_argument("-o", "--output", metavar="FILE", help="save results as JSON")
    args = parser.parse_args()

    if (args.start_port is None) != (args.end_port is None):
        parser.error("provide both START_PORT and END_PORT")
    if args.start_port is not None:
        if args.ports is not None:
            parser.error("use positional ports or --ports, not both")
        if not 1 <= args.start_port <= args.end_port <= 65535:
            parser.error("ports must be in ascending order between 1 and 65535")
        ports = list(range(args.start_port, args.end_port + 1))
    else:
        ports = args.ports if args.ports is not None else parse_ports(DEFAULT_PORTS)
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if not 1 <= args.workers <= 128:
        parser.error("--workers must be between 1 and 128")
    if args.banner and args.protocol == "udp":
        parser.error("--banner applies only to TCP")

    protocols = ("tcp", "udp") if args.protocol == "both" else (args.protocol,)
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    start_time = time.perf_counter()
    tasks = [(protocol, port) for protocol in protocols for port in ports]
    worker_count = min(args.workers, len(tasks))
    print(f"Scan started: {timestamp}")
    print(f"Checking {LOOPBACK} ({len(ports)} port(s), {worker_count} worker(s))")

    executor = ThreadPoolExecutor(max_workers=worker_count)
    futures = {}
    results: list[dict[str, object]] = []
    completed: set[object] = set()
    interrupted = False
    try:
        for protocol, port in tasks:
            future = executor.submit(run_check, protocol, port, args.timeout, args.banner)
            futures[future] = (protocol, port)
        for future in as_completed(futures):
            protocol, port = futures[future]
            state, banner = future.result()
            results.append({
                "port": port,
                "protocol": protocol,
                "state": state,
                "service": service_name(port, protocol),
                "banner": banner,
            })
            completed.add(future)
    except KeyboardInterrupt:
        interrupted = True
        for future in futures:
            future.cancel()
        for future, (protocol, port) in futures.items():
            if future.done() and future not in completed and not future.cancelled():
                try:
                    state, banner = future.result()
                except Exception:
                    continue
                results.append({
                    "port": port,
                    "protocol": protocol,
                    "state": state,
                    "service": service_name(port, protocol),
                    "banner": banner,
                })
    finally:
        executor.shutdown(wait=not interrupted, cancel_futures=interrupted)

    results.sort(key=lambda result: (str(result["protocol"]), int(result["port"])))
    duration = time.perf_counter() - start_time
    print_results(results, args.show_all)
    state_counts: dict[str, int] = {}
    for result in results:
        state = display_state(str(result["protocol"]), str(result["state"]))
        state_counts[state] = state_counts.get(state, 0) + 1
    print("Summary: " + (", ".join(
        f"{count} {state}" for state, count in sorted(state_counts.items())
    ) or "no completed checks"))
    print(f"Total scan time: {duration:.3f} seconds")
    if interrupted:
        print("Scan interrupted; showing completed results.")

    if args.output:
        report = {
            "target": LOOPBACK,
            "protocol": args.protocol,
            "timestamp": timestamp,
            "duration_seconds": duration,
            "results": results,
        }
        try:
            with open(args.output, "w", encoding="utf-8") as output_file:
                json.dump(report, output_file, indent=2)
                output_file.write("\n")
        except OSError as error:
            print(f"Could not write JSON output: {error}", file=sys.stderr)
            return 1
        print(f"Saved JSON results to {args.output}")
    return 130 if interrupted else 0


if __name__ == "__main__":
    sys.exit(main())