FROM python:3.11-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 GRADIO_SERVER_NAME=0.0.0.0
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python scripts/generate_data.py && python scripts/train_ml.py
RUN useradd -m rewa && chown -R rewa /app
USER rewa
EXPOSE 7860
CMD ["python", "app.py"]
