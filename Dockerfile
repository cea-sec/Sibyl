# This file is part of Sibyl.
# Copyright 2017 Camille MOUGEY <camille.mougey@cea.fr>
#
# Sibyl is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Sibyl is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Sibyl. If not, see <http://www.gnu.org/licenses/>.

FROM miasm/tested:latest
MAINTAINER Camille Mougey <camille.mougey@cea.fr>
USER root

# Get unicorn
RUN apt-get install -y python-pip &&\
    pip install --pre unicorn

# Get Sibyl
ADD https://github.com/cea-sec/Sibyl/archive/master.tar.gz /opt/Sibyl.tar.gz
RUN cd /opt &&\
    tar xzvf Sibyl.tar.gz &&\
    rm Sibyl.tar.gz &&\
    mv Sibyl-master Sibyl &&\
    chown -Rh miasm2 Sibyl &&\
    cd Sibyl &&\
    python setup.py install

# Prepare the environment
WORKDIR /opt/Sibyl
USER miasm2

CMD ["/usr/local/bin/sibyl"]
