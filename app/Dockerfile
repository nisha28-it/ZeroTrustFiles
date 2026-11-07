FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
RUN useradd --create-home appuser \
 && mkdir -p /data/storage /data/logs \
 && chown -R appuser:appuser /app /data
USER appuser
ENV PYTHONUNBUFFERED=1
EXPOSE 5000
CMD ["python", "app.py"]