#!/bin/sh

twistd -ny dns-filter.py --uid=$(id -u nobody) --gid=$(id -g nobody) --syslog
