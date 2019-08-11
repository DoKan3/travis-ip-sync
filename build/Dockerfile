FROM python:3.7

COPY requirements.txt /
RUN pip install -r /requirements.txt --no-build-isolation

WORKDIR /app
COPY travis_ip_sync.py /app/

CMD ["python", "travis_ip_sync.py"]
