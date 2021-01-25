FROM python:3.7-slim

# Install prerequisites
RUN apt-get update \
    && apt-get install -y \
        ca-certificates \
        xmlsec1 \
        libxmlsec1-dev \
        libxml2-dev \
        libxmlsec1-openssl \
        libffi6 \
        build-essential \
        libpq-dev \
        pkg-config \
        make \
        gcc \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# We copy just the requirements.txt first to leverage Docker cache
# (avoid rebuilding the requirements layer when application changes)
COPY ./requirements.txt /app/requirements.txt
WORKDIR /app
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# When started, the container checks for the required configuration files
# and if it can't find them, it uses the example files to make the server
# start.
#
# The example files won't be available if the user rebinds /app/conf,
# so we make a copy somewhere else.

# Copy the full application in a single layer
COPY . /app

EXPOSE 5000
VOLUME /app

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "app.py"]
