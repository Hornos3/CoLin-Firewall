# CoLin's Firewall -- Based on Linux

This is a student's project for Linux firewall.

Development environment: 
- Ubuntu version: Ubuntu 20.04
- Linux version: 5.15.0-83-generic
- Qt version: 5.12.8

## 0x01. Basic Functions

The firewall contains a kernel module and a GUI. The kernel module is used for hooking 5 hooks: PRE_ROUTING, LOCAL_IN, LOCAL_OUT, FORWARD and POST_ROUTING. The kernel module provides lots of interfaces for communication with the GUI.

Until the latest version, the firewall can manage:

- Add and delete rules.
- Inspect connections, rules and logs
- Do some settings.

Usage:
- `make` in dir 'kernel' to build the kernel module
- run `firewall_user` in dir 'user' to run GUI, the GUI will insert and remove kernel modules automatically

## 0x02. Kernel Interfaces

The firewall kernel module has many interfaces, including saving data, set rules, etc. All interfaces are provided through `ioctl` function with different command ids.

The chart of commands is shown below:

```
                           bits                         functions
       7     6     5     4     3     2     1     0
  1 |  0  |  0  |  1  |  0  |  1  |  1  |  1  |  1  |   set configs                         (tested)
  2 |  0  |  0  |  1  |  p  |  p  |  h  |  h  |  h  |   return rules                        (tested)
  3 |  0  |  0  |  1  |  1  |  1  |  1  |  0  |  1  |   set the filename for saving rules   (tested)
  4 |  0  |  0  |  1  |  1  |  1  |  1  |  1  |  0  |   get the filename for saving rules   (tested)
  5 |  0  |  0  |  1  |  1  |  1  |  1  |  1  |  1  |   add a rule for a hook               (tested)
  6 |  0  |  1  |  0  |  x  |  x  |  x  |  x  |  x  |   delete rules                        (tested)
  7 |  0  |  1  |  1  |  1  |  1  |  0  |  0  |  0  |   return connections                  (tested)
  8 |  0  |  1  |  1  |  1  |  1  |  0  |  0  |  1  |   save connections into a file        (will not test)
  9 |  0  |  1  |  1  |  1  |  1  |  0  |  1  |  0  |   clear logs                          (tested)
 10 |  0  |  1  |  1  |  1  |  1  |  0  |  1  |  1  |   return all saved logs               (will not test)
 11 |  0  |  1  |  1  |  1  |  1  |  1  |  0  |  0  |   save all logs into a file           (will not test)
 12 |  0  |  1  |  1  |  1  |  1  |  1  |  0  |  1  |   return newly generated logs         (tested)
 13 |  0  |  1  |  1  |  1  |  1  |  1  |  1  |  0  |   return current configs              (tested)
 14 |  0  |  1  |  1  |  1  |  1  |  1  |  1  |  1  |   save/load rules from a file         (tested)
 15 |  1  |  0  |  0  |  p  |  p  |  h  |  h  |  h  |   set default activity                (tested)
 * p for protocol bits, 0 for TCP, 1 for UDP, 2 for ICMP
 * h for hook id, 0: PRE_ROUTING, 1: LOCAL_IN, 2: LOCAL_OUT, 3: FORWARD, 4: POST_ROUTING
 * x for not important
 
      arg formats
  1   a config_user* pointer
  2   a user pointer of enough size
  3   a char* pointer
  4   a user pointer
  5   a rule_tbi* pointer
  6   if NULL: delete all rules, else: rule_tbd* pointer
  7   a user pointer of enough size, 3 LSB bit of the pointer for protocol id
  8   a char* pointer for filename
  9   protocol id, if PROTOCOL_SUPPORTED (3 for now): clear all logs, else: clear logs for a protocol
 10   a user pointer of enough size, 3 LSB bit of the pointer for protocol id
 11   a char* pointer for filename, 3 LSB bit of the pointer for protocol id
 12   a user pointer of enough size
 13   config id
 14   a char* pointer for filename, 3 LSB bit of the pointer: 0 for save, 1 for load
 15   bit 0: accept/reject, bit 1: log/no log, bit 7: get(from return value)/set (1/0)
```