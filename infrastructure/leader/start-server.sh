#!/usr/bin/env bash

# Wait for the volume to be mounted
until cd /opt/dike/codebase
do
    echo "Waiting.."
done

# Sleep
sleep infinity