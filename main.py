from icmplib import ping
import threading
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
import logging
logging.getLogger("scapy").setLevel(logging.CRITICAL)
from scapy.all import ICMP, sniff, IP
import click



def icmp_callback(packet: IP, my_ip: str| None=None):
    if packet.haslayer(ICMP):
        if my_ip is not None and packet[IP].src == my_ip:
            return
        layer = packet.getlayer(ICMP)
        if layer.type == 8:
            raw_payload = packet[ICMP].payload.original
            if len(raw_payload) > 0:
                decoded_payload = raw_payload.decode("utf-8")
                print(f"{packet[IP].src}: {decoded_payload}")
def start_sniffing(my_ip: str| None=None):
    sniff(filter="icmp", prn=icmp_callback, store=0)
def send_icmp_packet(ip: str, message: str):
    ping(ip, count=1, interval=0.2, timeout=1, payload=bytes(message, "utf-8"), privileged=False)

@click.command(help="Tento program Vám umožní si povídat s jiným počítačem pomocí pingů! Je potřeba jako argument zadat IP adresu počítače, se kterým si chcete psát.")
@click.argument("target", metavar="<target_ip>")
@click.option("--my-ip", "-m", required=False, help="Vaše IP adresa")
def main(target: str, my_ip: str| None=None):
    """
    Entry point of the program.

    Args:
        target_ip (str): The IP address of the target computer to communicate with.
        my_ip (str, optional): Your IP address. Defaults to None.
    """
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()
    session = PromptSession()

    with patch_stdout():
        try:
            while True:
                message = session.prompt(">> ", is_password=False)
                send_icmp_packet(target, message)
        except KeyboardInterrupt:
            print("Exiting...")
        except Exception as e:
            print(f"Error: {e}")
if __name__ == "__main__":
    main()