# Loopback Port Scanner

A small Python socket-programming project for checking TCP and UDP ports on the
computer running it. The target is intentionally fixed to `127.0.0.1`; this tool
does not scan other devices.

## Run

```powershell
python portscanner.py
python portscanner.py 1 100
python portscanner.py 1 100 --banner
python portscanner.py 8000 8005 --show-all
python portscanner.py --ports 80,443,8000-8010
python portscanner.py --protocol both --ports 53,80,443 --timeout 1 --workers 8
python portscanner.py --ports 22,80,8000 --banner -o report.json
python -m unittest test_portscanner
```

The positional form takes `START_PORT END_PORT` and checks that inclusive range
on `127.0.0.1`. The tool does not accept a target host. Use
`python portscanner.py --help` to see the available options. The default checks
a short list of common ports using TCP.

`--banner` passively reads up to 256 bytes from an open TCP connection. It only
shows text the local service sends on connect; services that wait for a request
may report no banner. The option does not apply to UDP.

The default timeout is 0.25 seconds and the default worker count is 64. Use
`--timeout 1` or `--timeout 3` when slower loopback refusal delivery needs more
time, and use `--workers` to tune concurrency.

By default, only open ports and UDP `open|filtered` results are printed. Add
`--show-all` to include closed and filtered results. Each row includes the
service name when the local service database knows it, and the final summary
reports state counts and elapsed time. `-o FILE` or `--output FILE` writes the
full results to JSON, including rows hidden from the table.

## Reading the results

- TCP `open` means a connection was accepted. `closed` means the target
  returned a connection refusal. A timeout is shown as `filtered / no response`;
  local firewall behavior can also affect the result.
- UDP `closed` means an ICMP port-unreachable response was received. A reply is
  evidence of an open service. No reply is shown as `open|filtered`, because
  UDP services often ignore datagrams and silence cannot distinguish an open
  port from a filtered one. The scanner sends a small DNS request on UDP 53, an
  NTP request on UDP 123, and a one-byte probe on other UDP ports.

## Compared with Nmap

This project demonstrates basic TCP connect checks and UDP datagram behavior.
It is intentionally much narrower than Nmap: it only checks loopback, has no
active service/version probing, SYN scan, operating-system detection, or
advanced filtering analysis. Its optional banner output is only a passive local
greeting, not comprehensive service detection. Nmap is the appropriate tool for
authorized network assessment; this project is a learning exercise, not a
replacement.