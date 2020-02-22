#!/bin/bash

echo 'terminating prior instances'

./killall.sh
./kill_controller

sleep 1

echo 'starting pox'
pkill -f pox.py
./run_pox.sh &

sleep 3
echo 'waiting for pox'
sleep 7

echo 'starting mininet'
sudo python lab7-topology.py

echo 'terminating pox'
pkill -f pox.py

sleep 1

./killall.sh
./kill_controller
