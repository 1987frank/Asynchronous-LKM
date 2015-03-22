#!/bin/sh
set -x
lsmod
rmmod xjob
insmod xjob.ko
lsmod
