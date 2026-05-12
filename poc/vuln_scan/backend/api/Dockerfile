FROM python:3.11-slim

WORKDIR /app

COPY backend/llm/requirements.txt /tmp/llm-requirements.txt
COPY backend/api/requirements.txt /tmp/api-requirements.txt
RUN pip install --no-cache-dir \
    -r /tmp/llm-requirements.txt \
    -r /tmp/api-requirements.txt

ENV PYTHONPATH=/app:/llm/src

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
