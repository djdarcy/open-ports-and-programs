# open-ports-and-programs.py

**open-ports-and-programs.py** is a cross-platform Python script that enumerates local network connections (both listening and non-listening), listing the corresponding ports, process names, PIDs, and optional DNS lookups. It acts as a flexible alternative to classic tools like `netstat` or `lsof`, incorporating regex-based filtering, continuous monitoring, and various sorting options.

## Features

1. **Port & Process Mapping**  
   - Automatically discovers open ports and correlates them to processes/PIDs using `psutil`.

2. **Sorting Options**  
   - Sort by **PID**, **Port**, or **Program** name for easy navigation of large connection lists.

3. **Regex Filtering**  
   - Include or exclude connections by process name or ports using regex (e.g., `-r "(chrome|firefox|opera)"`).

4. **Continuous Monitoring**  
   - With `-c/--continuous [INTERVAL]`, repeatedly update the list of open ports for real-time tracking.

5. **DNS Resolution**  
   - Use `-d/--dns` to resolve remote IP addresses to hostnames, providing more recognizable output.

6. **Bare Output for Scripting**  
   - `-b/--bare` yields minimal formatting, perfect for piping or further script consumption.

## Installation

1. **Clone the Repository**  
   ```bash
   git clone https://github.com/djdarcy/dazzle.git
   cd dazzle

2. **Install Dependencies**

```
pip install psutil pytz
```

- **psutil**: to inspect processes and network connections.
- **pytz**: (and the standard library `datetime`) handle timezones for the script’s output.

3. **Run the Script**

```
python open-ports-and-programs.py [options]
```

## Usage Examples

### 1. Basic Invocation

List all listening and non-listening connections, sorted by Program (default):

```
python open-ports-and-programs.py
```

### 2. Sort by Port

```
python open-ports-and-programs.py --port
```

Equivalent to `-p`, sorts results by numeric port values.

### 3. Show Only Listening Connections

```
python open-ports-and-programs.py --listening
```

Limits results to just connections in the `LISTEN` state.

### 4. Continuous Monitoring

```
# Refresh every 5 seconds, sorting by Port
python open-ports-and-programs.py -p --continuous 5
```

### 5. Filter by Regex

```
# Only show connections for Chrome, Firefox, or Opera; sort by PID
python open-ports-and-programs.py --pid --regex "(chrome|firefox|opera)"
```

### 6. Resolve DNS

```
python open-ports-and-programs.py --dns
```

Converts remote IPs to hostnames.

## Command-Line Options / Reference

| Argument                  | Description                                                                 |
| ------------------------- | --------------------------------------------------------------------------- |
| `-i, --pid`              | Sort output by PID (Process ID).                                            |
| `-p, --port`             | Sort output by Port.                                                        |
| `-s {PID,Port,Program}, --sort {PID,Port,Program}` | Sort by PID, Port, or Program (default: Program).                           |
| `-b, --bare`             | Bare output format, suitable for use in scripts.                            |
| `-l, --listening`        | Show only connections in the `LISTEN` state.                                |
| `-d, --dns`              | Resolve remote IP addresses to domain names for better readability.         |
| `-r REGEX, --regex REGEX`| Filter connections using a regex pattern applied to process names or ports. |
| `-c [CONTINUOUS], --continuous [CONTINUOUS]` | Continuously monitor network connections at the specified interval in seconds (default: 10s). |
| `-h, --help`             | Show the help message and exit.                                             |

## Known Limitations

1. **DNS Resolution Overhead**
   - Repeated DNS lookups in `--continuous` mode can slow performance. Consider caching or skipping DNS for large lists.
2. **PID Caching**
   - PIDs are retrieved repeatedly for each connection, which adds overhead. A simple memoization or dictionary cache could make frequent scans more efficient.
3. **Platform Permissions**
   - Some OSes require elevated privileges or additional permissions for listing certain connections or processes.

## Contributing

Contributions are welcome. Feel free to:

1. Fork the repository.
2. Make changes on a new branch (e.g., `feature/add-protocol-filter`).
3. Submit a pull request with a clear description of your modifications.

Like the project?

[!["Buy Me A Coffee"](https://camo.githubusercontent.com/0b448aabee402aaf7b3b256ae471e7dc66bcf174fad7d6bb52b27138b2364e47/68747470733a2f2f7777772e6275796d6561636f666665652e636f6d2f6173736574732f696d672f637573746f6d5f696d616765732f6f72616e67655f696d672e706e67)](https://www.buymeacoffee.com/djdarcy)


## License

open-ports-and-programs.py, Copyright (C) 2025 Dustin Darcy

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/.
