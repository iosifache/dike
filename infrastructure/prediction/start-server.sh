#!/usr/bin/env bash

# Wait for the volume to be mounted and install the requirements
until cd /dike/dike && pip install -r requirements.txt
do
    echo "Retrying pip install.."
done

# Run the program
cd /dike/dike/prediction
python app.py