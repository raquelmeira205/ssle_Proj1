# One Dockerfile for all services.
#   docker build --build-arg SERVICE=storage --build-arg PORT=5002 -t ssle/storage .
FROM python:3.12-slim
ARG SERVICE
ARG PORT=5000
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY common.py .
COPY ${SERVICE}/ .
EXPOSE ${PORT}
# the registry and the services have app.py; the sensor has sensor.py
CMD ["sh", "-c", "if [ -f app.py ]; then python app.py; else python sensor.py; fi"]
