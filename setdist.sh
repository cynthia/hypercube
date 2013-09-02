#!/bin/sh
echo "#define SERVER_DIST \"`date` `whoami`@`hostname`\"" > dist.h
