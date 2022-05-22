#!/bin/bash

# Cleanup

echo "Cleaning containers"
sudo docker rm -f $(docker ps -q)
sudo docker container prune -f

echo "Cleaning networks"
sudo docker network rm $(docker network ls -q)