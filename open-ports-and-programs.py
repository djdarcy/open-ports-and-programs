import sys
import time
import re
import argparse
import socket
import psutil

import datetime
import pytz


class CustomHelpFormatter(argparse.RawDescriptionHelpFormatter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def format_help(self):
        help_text = super().format_help()
        footer = '''
open-ports-and-programs.py v1.0 (https://github.com/djdarcy/dazzle)
Dustin Darcy @ <dustin.darcy.code (at) gmail (dot) com> | http://scarcityhypothesis.org
'''
        return help_text + footer

class CustomArgumentParser(argparse.ArgumentParser):
    def parse_args(self, *args, **kwargs):
        args = super().parse_args(*args, **kwargs)
        return args

    def __init__(self, *args, **kwargs):

        kwargs["formatter_class"] = CustomHelpFormatter
        kwargs["description"] = f"""
List open ports and corresponding programs. Optionally, filter by program name, port, or connection count.
 * Similar to `netstat -anob | tasklist /fi "pid eq ###"`, but with more options and a more concise output.

Examples:
  open-ports-and-programs.py -pd -r "(chrome|msedge|opera)" -c 5
   # Lists open ports and corresponding programs sorting by local ports (-p) with DNS enabled (-d),
   # but only for programs matching the regex "(chrome|msedge|opera)" (-r). After this, it continuously
   # updates the output (-c 5) every 5 seconds.

Note: 
  -r matching will not check against DNS names even with -d (DNS) enabled.

"""
        super().__init__(None, **kwargs)   #NOTE: Remember we can't pass args because __init__ prints JSON

    def error(self, message):
        self.print_help()
        sys.stderr.write(f'\n\nError: {message}\n')
        sys.exit(2)

class OutputManager:
    _instance = None
    _bare = False
    _max_program_len = 30
    _max_line_len = 0
    _header_displayed = False

    @property
    def _formatter(self):
        #return '{{:<6}} {{:<{}}} {{:<6}} {{:>20}}'.format(self._max_program_len)
        return '{{:<6}} {{:<{}}} {{:<6}}'.format(self._max_program_len)
    
    @property
    def _header(self):
        return (self._formatter + ' {:>20}').format('Port:', 'Program', 'PID', 'Svc Name / Foreign Addr')
    
    @property
    def _header_len(self):
        return len(self._header)
    
    @property
    def _separator(self):
        return '{}'.format('-' * self._max_line_len)

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(OutputManager, cls).__new__(cls)
            cls._instance.bare = False
        return cls._instance

    def calculate_max_line_len(self, connections, dns=False):
        max_line_len = 0
        for port, (pid, program, foreign_address) in connections:
            line = self.output(port, program, pid, foreign_address, dns) #dns=false too slow otherwise
            max_line_len = max(max_line_len, len(line))
        self._max_line_len = max_line_len

    def print_header(self, state, bState=True, bHeader=False, bSeparator=False):
        # Get the current time in seconds since epoch
        current_time = time.time()
        # Get the local timezone offset in seconds
        local_timezone_offset = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
        # Convert the timezone offset to hours and minutes
        timezone_hours = abs(local_timezone_offset) // 3600
        timezone_minutes = (abs(local_timezone_offset) // 60) % 60
        # Format the timezone offset as '+HH:MM' or '-HH:MM'
        timezone_offset_str = f"+{timezone_hours:02}:{timezone_minutes:02}" if local_timezone_offset >= 0 else f"-{timezone_hours:02}:{timezone_minutes:02}"
        # Format the current time with the local timezone offset
        #formatted_now = time.strftime('%y.%m.%d %H:%M:%S [{}]'.format(timezone_offset_str), time.localtime(current_time))
        formatted_now = time.strftime('%y.%m.%d %H:%M:%S ({})'.format(timezone_offset_str), time.localtime(current_time))


        centered_state = ( state+f" ({formatted_now})").center(self._max_line_len, '-')
        if self._bare:
            return
        if bState:
            print(centered_state)
        if bHeader: 
            print(self._header)
        if bSeparator:
            print(self._separator)

    def print_section(self, state, connections, lines_before=0, lines_after=0, bState=True, bHeader=False, bSeparator=False, dns=False):
        self.calculate_max_line_len(connections) #bug: should be able to pass in dns, but too slow
        if(connections == []):
            return
        if(self._header_displayed == False):
            self._header_displayed = True
            lines_before = 0
            bHeader = True
            bSeparator = True

        print('\n' * lines_before, end='')
        if not self._bare:
            self.print_header(state, bState, bHeader, bSeparator)
        for port, (pid, program, foreign_address) in connections:
            line = self.output(port, program, pid, foreign_address, dns)
            print(line)
        print('\n' * lines_after, end='')

    def set_bare(self, bare):
        self._bare = bare

    def set_max_program_len(self, max_program_len):
        if type(max_program_len) != int and type(max_program_len) == str:
            try:
                max_program_len = int(len(max_program_len))
            except ValueError:
                raise TypeError('max_program_len must be an integer')
        if max_program_len > self._max_program_len:
            self._max_program_len = max_program_len

    def output(self, port, program, pid, foreign_address=(), dns=False):
        program = program if program else '<unknown>'
        foreign_address_str = f'{foreign_address.ip}:{foreign_address.port}' if foreign_address else ''
        if dns and foreign_address:
            foreign_address_str = foreign_address_str + " (" + socket.getfqdn(foreign_address.ip) + ")"
        service_name = ''
        try:
            service_name = socket.getservbyport(port)
        except Exception as e:
            pass

        preformat = OutputManager()._formatter
        if self._bare:
            line = preformat.format(port, program, pid, foreign_address_str)
            #line = f'{port:<6} {program:<{self._max_program_len}} {pid:<6} {foreign_address_str:>20}'
        else:
            if service_name and foreign_address_str:
                #shouldn't happen (trying to compress svc name and foreign addr into 40 chars)
                line = (preformat + f'{"SVC: "+service_name:<10}' + ' {:>40}').format(port, program, pid, foreign_address_str)
            elif service_name and foreign_address_str == '':
                #left align service name with 20 chars (no foreign addr)
                line = (preformat + f'{"SVC: "+service_name:<20}').format(port, program, pid, foreign_address_str)
            else:
                #right aligned with 40 chars for IPV6 and DNS
                line = (preformat + '{:>40}').format(port, program, pid, foreign_address_str)
        return line

def get_program_by_pid(pid):
    try:
        p = psutil.Process(pid)
        return p.name()
    except psutil.NoSuchProcess:
        return None

def process_connection(connection, listening_mapping, non_listening_mapping, sort_by, foreign_address=False):
    port = connection.laddr.port
    pid = connection.pid
    foreign_address = connection.raddr
    program = get_program_by_pid(pid)
    if connection.status == 'LISTEN':
        listening_mapping[port] = (pid, program, foreign_address)
    else:
        non_listening_mapping[port] = (pid, program, foreign_address)

def get_port_program_mapping(sort_by, bare, listening_only=False, dns=False, regex=None):
    OutputManager().set_bare(bare)
    listening_mapping = {}
    non_listening_mapping = {}
    all_connections = psutil.net_connections()

    # Compile regex pattern if provided
    try:
        pattern = re.compile(regex) if regex else None
    except re.error as e:
        print(f'Error: {e}')

    for connection in all_connections:
        if listening_only and connection.status != 'LISTEN':
            continue
        if pattern and not pattern.search(str(connection)) and not pattern.search(get_program_by_pid(connection.pid)):
            continue
        process_connection(connection, listening_mapping, non_listening_mapping, sort_by)
        OutputManager().set_max_program_len(get_program_by_pid(connection.pid))

    if sort_by == 'PID':
        sorted_listening = sorted(listening_mapping.items(), key=lambda x: int(x[1][0]))
        sorted_non_listening = sorted(non_listening_mapping.items(), key=lambda x: int(x[1][0]))
    elif sort_by == 'Port':
        sorted_listening = sorted(listening_mapping.items(), key=lambda x: int(x[0]))
        sorted_non_listening = sorted(non_listening_mapping.items(), key=lambda x: int(x[0]))
    elif sort_by == 'Program':
        sorted_listening = sorted(listening_mapping.items(), key=lambda x: x[1][1] if x[1][1] else '')
        sorted_non_listening = sorted(non_listening_mapping.items(), key=lambda x: x[1][1] if x[1][1] else '')
    else:
        sorted_listening = sorted(listening_mapping.items(), key=lambda x: int(x[0]))
        sorted_non_listening = sorted(non_listening_mapping.items(), key=lambda x: int(x[0]))

    OutputManager().print_section("LISTENING", sorted_listening, dns=dns, lines_before=1)  # redundant now: bHeader=True, bSeparator=True, 
    if not listening_only:
        OutputManager().print_section("NON-LISTENING", sorted_non_listening, lines_before=1, dns=dns)

    return listening_mapping, non_listening_mapping


if __name__ == '__main__':
    parser = CustomArgumentParser(description='List open ports and corresponding programs', formatter_class=CustomHelpFormatter)
    parser.add_argument('-i', '--pid', action='store_true', help='Sort by PID')
    parser.add_argument('-p', '--port', action='store_true', help='Sort by Port')
    parser.add_argument('-s', '--sort', choices=['PID', 'Port', 'Program'], default='Program', help='Sort by PID, Port, or Program (default: %(default)s)')

    parser.add_argument('-b', '--bare', action='store_true', help='Bare output, suitable for scripts')
    parser.add_argument('-l', '--listening', action='store_true', help='Show only listening connections')
    parser.add_argument('-d', '--dns', action='store_true', help='Resolve IP addresses to domain names')
    parser.add_argument('-r', '--regex', type=str, help='Regex pattern to filter output')
    parser.add_argument('-c', '--continuous', type=int, nargs='?', const=10, help='Continuously monitor network connections at specified interval in seconds (default: 10s)')

    args = parser.parse_args()
    
    if args.pid:
        args.sort = 'PID'
    elif args.port:
        args.sort = 'Port'

    while True:
        try:
            get_port_program_mapping(args.sort, args.bare, args.listening, args.dns, args.regex)
            if args.continuous is None:
                break
            time.sleep(args.continuous)
        except KeyboardInterrupt:
            print('\nMonitoring stopped.')
            break

