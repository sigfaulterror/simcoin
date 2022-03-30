from blessings import Terminal
from threading import current_thread
from datetime import datetime
terminal = Terminal()
(ERROR, INFO, SUCCESS) = (0, 1, 2)

def log(msg, level):
    if level == ERROR:
        sym = terminal.red(' [-] ')
    if level == INFO:
        sym = terminal.yellow(' [!] ')
    if level == SUCCESS:
        sym = terminal.green(' [+] ')
    thread_name = current_thread().getName()
    local_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-2]
    msg = ' {} [{}] {} -- {}'.format(sym, thread_name, local_time, msg)
    print(msg)
