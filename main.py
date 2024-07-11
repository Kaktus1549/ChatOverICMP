from icmplib import ping
import threading
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
import logging
logging.getLogger("scapy").setLevel(logging.CRITICAL)
from scapy.all import ICMP, sniff, IP
import click
import random

host_ip = None
bad_words = ["kokot", "debil", "idiot", "sračka", "sračko", "sračky", "sračky", "negr", "neggr" "nigga"]

def icmp_callback(packet: IP):
    if packet.haslayer(ICMP):
        if host_ip is not None and packet[IP].src == host_ip:
            return
        layer = packet.getlayer(ICMP)
        if layer.type == 8:
            raw_payload = packet[ICMP].payload.original
            if len(raw_payload) > 0:
                try:
                    decoded_payload = raw_payload.decode("utf-8")
                    if decoded_payload == "abcdefghijklmnopqrstuvwabcdefghi":
                        print(f"Detected ping from windows machine: {packet[IP].src}")
                        return
                    print(f"{packet[IP].src}: {decoded_payload}")
                except UnicodeDecodeError:
                    pass
                except Exception as e:
                    print(f"Error: {e}")
def start_sniffing(my_ip: str| None=None):
    sniff(filter="icmp", prn=icmp_callback, store=0)
def send_icmp_packet(ip: str, message: str):
    if len(message) > 0:
        if len(message) >= 60:
            if message in bad_words:
                rand = random.randint(0, 1)
                if rand == 1:
                    print("Zpráva obsahuje zakázané slovo womp womp")
                else:
                    print("Skill issue bud slysny priste")
                return
            print("Zpráva je moc dlouhá :((")
            return
        ping(ip, count=1, interval=0.2, timeout=1, payload=bytes(message, "utf-8"), privileged=False)
    elif len(message) == 0:
        return
@click.command(help="Tento program Vám umožní si povídat s jiným počítačem pomocí pingů! Je potřeba jako argument zadat IP adresu počítače, se kterým si chcete psát.")
@click.argument("target", metavar="<target_ip>")
@click.option("--my-ip", "-m", required=False, help="Vaše IP adresa")
def main(target: str, my_ip: str|None=None):
    """
    Entry point of the program.

    Args:
        target_ip (str): The IP address of the target computer to communicate with.
        my_ip (str, optional): Your IP address. Defaults to None.
    """
    global host_ip

    host_ip = my_ip
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