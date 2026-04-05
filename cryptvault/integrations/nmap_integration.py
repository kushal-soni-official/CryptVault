import nmap

def scan_target(target: str) -> dict:
    """Run an Nmap scan against a target."""
    nm = nmap.PortScanner()
    # Using a simple default scan (TCP connect, top 100 ports, fast)
    nm.scan(target, arguments='-F -sT')
    
    results = {}
    for host in nm.all_hosts():
        results[host] = {
            'state': nm[host].state(),
            'protocols': {}
        }
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            results[host]['protocols'][proto] = []
            for port in sorted(ports):
                port_info = nm[host][proto][port]
                results[host]['protocols'][proto].append({
                    'port': port,
                    'state': port_info['state'],
                    'name': port_info['name']
                })
    return results
