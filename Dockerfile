# Single image, shared by all three services in docker-compose.yml
# (api, api-secure, detector) - each container just runs a different
# entrypoint command against the same codebase.
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api/ api/
COPY detector/ detector/
COPY attacks/ attacks/

# logs/ and alerts/ are bind-mounted from the host in docker-compose.yml,
# not baked into the image - that's the shared state the services
# coordinate through.
RUN mkdir -p logs alerts

EXPOSE 5000 5001

CMD ["python", "api/app.py"]
