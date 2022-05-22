#!/bin/bash

sudo docker rm -f $(docker ps -q)
sudo docker container prune -f

sudo docker network rm $(docker network ls -q)
