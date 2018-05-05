FROM python:3.6

RUN pip install boto3 premailer pyyaml first

# install nodejs and privnote-cli
# privnote-cli npm install fails on node 8.10.0, works on 4.7.3
RUN cd /usr/local && \
	wget https://nodejs.org/dist/v4.7.3/node-v4.7.3-linux-x64.tar.xz && \
	tar -C /usr/local --strip-components 1 -xf node-v4.7.3-linux-x64.tar.xz && \
	node --version && \
	npm install -g privnote-cli

# install terraform
RUN apt-get update -y && \
	apt-get install -y wget unzip dos2unix && \
	wget https://releases.hashicorp.com/terraform/0.11.5/terraform_0.11.5_linux_amd64.zip && \
	unzip terraform_0.11.5_linux_amd64.zip -d /usr/local/bin/ && \
	terraform --version

ADD ./src /src
ADD ./tests /tests
ADD ./terraform /terraform
ADD ./content /content

# make sure the text isn't malformed if built on a windows host
RUN apt-get update -y && \
	apt-get install -y dos2unix && \
	dos2unix /src/*.py

WORKDIR /src

# make python behave in docker
ENV PYTHONUNBUFFERED=1
ENV PYTHONIOENCODING=utf8

# boto3 log level
ENV LOGLEVEL=WARNING

ENV IAMTOOL_DYNAMODB_CONFIG_TABLE_NAME=iamusertool_config
ENV IAMTOOL_SES_TEMPLATE_NAME=iamtool_welcome

ENTRYPOINT ["python3", "-u", "main.py"]
