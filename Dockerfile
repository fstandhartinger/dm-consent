FROM python:3.12-slim
RUN pip install --no-cache-dir "psycopg[binary]==3.2.3" && useradd -u 10001 -m app
WORKDIR /app
COPY app.py .
USER app
ENV PORT=8080 PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python", "app.py"]
