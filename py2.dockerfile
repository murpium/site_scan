FROM python:2.7

WORKDIR /usr/src/app

COPY requirements2.7.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT [ "python", "./site_scan.py" ]
