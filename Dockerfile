FROM python
RUN pip install -r requiremenets.txt
RUN apt-get install -y git sed timeout
RUN git clone https://github.com/github/advisory-database /src