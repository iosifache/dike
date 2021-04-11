# Set the base image
FROM python

# Set the working directory
WORKDIR /

# Expose the used ports
EXPOSE 3804 443

# Install OpenJDK and serve
RUN apt-get update
RUN apt-get -y install openjdk-11-jdk-headless nodejs npm
RUN npm install -g serve

# Install the Python3 requirements
ADD requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

# Add the codebase to the Python path
ENV PYTHONPATH "${PYTHONPATH}:/opt/dike/codebase"

# Run the startup script
COPY start-server.sh /
RUN ["chmod", "+x", "start-server.sh"]
CMD /start-server.sh