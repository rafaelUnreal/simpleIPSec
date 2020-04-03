#!/bin/bash

gcc encode.c ike.c serialize.c dh.c -l crypto -g

