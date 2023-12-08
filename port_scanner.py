import socket
import time
import common_ports
import re

REG_IS_IP = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
REG_IS_URL = re.compile(r'^(?:[0-9A-z.]+.)?[0-9A-z.]+.[a-z]+$')

def is_valid_ip(ip_address: str) -> bool:
  return REG_IS_IP.match(ip_address)


def is_valid_url(url: str) -> bool:
  return REG_IS_URL.match(url)

def get_verbose_scan(scan: list) -> str:
  result = ""
  if len(scan) > 0:
      for key, port in enumerate(scan):
          nb_spaces = 9 - len(str(port))
          spacer = " " * nb_spaces
          if key > 0:
              result += '\n'
          if port in common_ports.ports_and_services:
              result += "%s%s%s" % (
                  port,
                  spacer,
                common_ports.ports_and_services.get(port)
              )
          else:
              result += "%s%s%s" % (port, spacer, "Unkwonwn")
  return result

def init_socket():
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.settimeout(1)
  return s


def get_open_ports(target, port_range, verbose=False):
  open_ports = []
  for port in range(port_range[0], port_range[1]+1):
    s = init_socket()
    try:
      if not s.connect_ex((target, port)):
        open_ports.append(port)
    except Exception:
      time.sleep(0)
    s.close()
    time.sleep(0.1)

  if (verbose):
    target_string = ""
    if is_valid_url(target):
      ip = socket.gethostbyname(target)
      target_string = "Open ports for %s (%s)\n" % (target, ip)
    elif is_valid_ip(target):
      try:
        host = socket.gethostbyaddr(target)[0]
        target_string = "Open ports for %s (%s)\n" % (host, target)
      except Exception:
        target_string = "Open ports for %s\n" % (target)      
    st = target_string + "PORT     SERVICE\n"
    st += get_verbose_scan(open_ports)
    return st

  return (open_ports)
