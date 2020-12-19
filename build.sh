#!/bin/bash

gcc ike.c config.c encode.c serialize.c dh.c crypto.c -l crypto -l config -g -DDEBUG -o startIpsec
