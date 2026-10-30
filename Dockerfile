FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
RUN useradd -r -u 10001 appuser && mkdir -p /data && chown -R appuser:appuser /data /app
USER appuser
ENV DB_PATH=/data/confere.sqlite3 SESSION_HTTPS_ONLY=true
EXPOSE 8000
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8000","--proxy-headers","--forwarded-allow-ips","*"]
