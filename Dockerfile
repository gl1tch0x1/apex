FROM python:3.11
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
RUN playwright install
RUN apt-get update && apt-get install -y redis-server
CMD ["python", "main.py"]