FROM ubuntu:latest
WORKDIR /code
ENV DEBIAN_FRONTEND=noninteractive
RUN DEBIAN_FRONTEND="noninteractive" TZ="Europe/Brussels" apt-get update && apt-get -y install apt-utils
RUN DEBIAN_FRONTEND="noninteractive" TZ="Europe/Brussels" apt-get update && apt-get -y install tzdata \
	gcc \
	g++ \
	cmake \
	bash \
	git \
	make \
	ninja-build \
	netcat-openbsd \
	python3 \
	wget \
	lsb-release \
	sudo \
	psmisc \
	udev

#
# Change default user, we don't need root privileges
#

RUN groupadd --gid 5001 pcapfs
RUN useradd --home-dir /home/pcapfs \
      --create-home --uid 5001 --gid 5001 \
      --shell /bin/sh --skel /dev/null pcapfs
WORKDIR /home/pcapfs

RUN usermod -a -G sudo pcapfs

RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER pcapfs

COPY --chown=pcapfs:pcapfs build.sh build.sh
RUN chmod +x build.sh
RUN ./build.sh
