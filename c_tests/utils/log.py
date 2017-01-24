colors = {"red": "\033[91;1m",
          "end": "\033[0m",
          "green": "\033[92;1m",
          "lightcyan": "\033[96m",
          "blue": "\033[94;1m"}

def log_error(content):
    msg = "%(red)s[-] " % colors + content + "%(end)s" % colors
    print msg

def log_success(content):
    msg = "%(green)s[+] " % colors + content + "%(end)s" % colors
    print msg

def log_info(content):
    print "[+] "+content
