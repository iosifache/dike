# Set the base image
FROM python

# Set the working directory
WORKDIR /

# Install the Python3 requirements
ADD requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

# Add the codebase to the Python path
ENV PYTHONPATH "${PYTHONPATH}:/opt/dike/codebase"

# Run the startup script
COPY start-server.sh /
RUN chmod +x start-server.sh
CMD /start-server.sh