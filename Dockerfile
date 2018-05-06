FROM python:3

RUN mkdir -p /app
WORKDIR /app

COPY requirements*.txt /app/
RUN pip install --no-cache-dir -r requirements.txt -r requirements.production.txt

COPY . /app
RUN pip install --no-cache-dir .

ENTRYPOINT ["/app/run.sh"]
CMD ["app"]
