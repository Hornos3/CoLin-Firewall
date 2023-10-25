# CoLin's Firewall -- Based on Linux

This is a student's project for Linux firewall.

Development environment: 
- Ubuntu version: Ubuntu 20.04
- Linux version: 5.15.0-87-generic
- Qt version: 5.12.8

## 0x01. Basic Functions

The firewall contains a kernel module and a GUI. The kernel module is used for hooking 2 hooks: PRE_ROUTING and POST_ROUTING. The kernel module provides lots of interfaces for communication with the GUI.

Until the latest version, the firewall can manage:

- Add and delete rules.
- Inspect connections, rules and logs
- Do some settings.

Usage:
- `make` in dir 'kernel' to build the kernel module
- build the GUI in dir 'user'
- run `firewall_user` in dir 'user' to run GUI, the GUI will insert and remove kernel modules automatically

## 0x02. Kernel Interfaces

The firewall kernel module has many interfaces, including saving data, set rules, etc. All interfaces are provided through `ioctl` function with different command ids.

The chart of commands is shown below:

```
                           bits                         functions
       7     6     5     4     3     2     1     0
  1 |  0  |  0  |  1  |  0  |  1  |  1  |  0  |  1  |   return pat rules
  2 |  0  |  0  |  1  |  0  |  1  |  1  |  1  |  0  |   add/delete a nat rule
  3 |  0  |  0  |  1  |  0  |  1  |  1  |  1  |  1  |   set configs                         (tested)
  4 |  0  |  0  |  1  |  p  |  p  |  x  |  x  |  h  |   return rules                        (tested)
  5 |  0  |  0  |  1  |  1  |  1  |  1  |  0  |  1  |   set the filename for saving rules   (tested)
  6 |  0  |  0  |  1  |  1  |  1  |  1  |  1  |  0  |   get the filename for saving rules   (tested)
  7 |  0  |  0  |  1  |  1  |  1  |  1  |  1  |  1  |   add a rule for a hook               (tested)
  8 |  0  |  1  |  0  |  x  |  x  |  x  |  x  |  x  |   delete rules                        (tested)
  9 |  0  |  1  |  1  |  1  |  1  |  0  |  0  |  0  |   return connections                  (tested)
 10 |  0  |  1  |  1  |  1  |  1  |  0  |  0  |  1  |   save connections into a file        (will not test)
 11 |  0  |  1  |  1  |  1  |  1  |  0  |  1  |  0  |   clear logs                          (tested)
 12 |  0  |  1  |  1  |  1  |  1  |  0  |  1  |  1  |   return all saved logs               (will not test)
 13 |  0  |  1  |  1  |  1  |  1  |  1  |  0  |  0  |   save all logs into a file           (will not test)
 14 |  0  |  1  |  1  |  1  |  1  |  1  |  0  |  1  |   return newly generated logs         (tested)
 15 |  0  |  1  |  1  |  1  |  1  |  1  |  1  |  0  |   return current configs              (tested)
 16 |  0  |  1  |  1  |  1  |  1  |  1  |  1  |  1  |   save/load rules from a file         (tested)
 17 |  1  |  0  |  0  |  p  |  p  |  x  |  x  |  h  |   set default activity                (tested)
 * p for protocol bits, 0 for TCP, 1 for UDP, 2 for ICMP
 * h for hook id, 0: PRE_ROUTING, 1: POST_ROUTING
 * x for not important
 
      arg formats
  1   a user pointer of enough size
  2   a nat_config* pointer, lsb = 0 for add, others for delete
  3   a config_user* pointer
  4   a user pointer of enough size
  5   a char* pointer
  6   a user pointer
  7   a rule_tbi* pointer
  8   if NULL: delete all rules, else: rule_tbd* pointer
  9   a user pointer of enough size, 3 LSB bit of the pointer for protocol id
 10   a char* pointer for filename
 11   protocol id, if PROTOCOL_SUPPORTED (3 for now): clear all logs, else: clear logs for a protocol
 12   a user pointer of enough size, 3 LSB bit of the pointer for protocol id
 13   a char* pointer for filename, 3 LSB bit of the pointer for protocol id
 14   a user pointer of enough size
 15   config id
 16   a char* pointer for filename, 3 LSB bit of the pointer: 0 for save, 1 for load
 17   bit 0: accept/reject, bit 1: log/no log, bit 7: get(from return value)/set (1/0)
```