#!/usr/bin/python3
"""Wazuh active response for the k3s nodes: block a source IP for traffic to the PODS.

Why not the stock firewall-drop: it adds `-A INPUT -s <ip> -j DROP`, but traffic to a NodePort is
rewritten by kube-proxy (DNAT, nat/PREROUTING) and then FORWARDED to the pod, so it never crosses
INPUT. Here the DROP goes into the raw table's PREROUTING chain, which runs before kube-proxy.
With externalTrafficPolicy: Local a client that hits a node only reaches pods on that node, and
the agent of that node is the one that raises the alert, so blocking locally is enough.

Installed as /var/ossec/active-response/bin/k3s-block on each k3s node
(k3s/install-wazuh-node-agents.sh). Bound to rule 100210 with a 60 s timeout
(wazuh/manager-active-response-k3s.xml). Wazuh 4.x protocol: execd writes one JSON message on
stdin; for "add" the script answers "check_keys" and waits for "continue"/"abort"; after the
timeout execd runs the script again with "delete".
"""
import datetime
import ipaddress
import json
import subprocess
import sys

LOG = "/var/ossec/logs/active-responses.log"
NAME = "k3s-block"


def log(msg):
    with open(LOG, "a") as f:
        f.write(f"{datetime.datetime.now():%Y/%m/%d %H:%M:%S} active-response/bin/{NAME}: {msg}\n")


def read_msg():
    line = sys.stdin.readline()
    log(line.strip())
    return json.loads(line)


def rule(op, ip):
    return ["iptables", "-t", "raw", op, "PREROUTING", "-s", ip, "-j", "DROP"]


def present(ip):
    return subprocess.run(rule("-C", ip), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def main():
    log("Starting")
    msg = read_msg()
    command = msg.get("command")
    try:
        ip = str(ipaddress.ip_address(msg["parameters"]["alert"]["data"]["srcip"]))
    except (KeyError, ValueError):
        log("no valid srcip in the alert, nothing to do")
        return

    if command == "add":
        print(json.dumps({"version": 1, "origin": {"name": NAME, "module": "active-response"},
                          "command": "check_keys", "parameters": {"keys": [ip]}}), flush=True)
        if read_msg().get("command") != "continue":
            log(f"{ip} already handled by a running instance, aborting")
            return
        if not present(ip):
            subprocess.run(rule("-I", ip), check=False)
        log(f"blocked {ip} (raw PREROUTING)")
    elif command == "delete":
        while present(ip):
            subprocess.run(rule("-D", ip), check=False)
        log(f"unblocked {ip}")
    else:
        log(f"unknown command {command}")


if __name__ == "__main__":
    try:
        main()
    finally:
        log("Ended")
