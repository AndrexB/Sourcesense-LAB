FROM python:3.11-alpine
WORKDIR /app
COPY requirements.txt ./
# -- AGGIUNGI I PACCHETTI DI BUILD --
RUN apk add --no-cache gcc python3-dev musl-dev linux-headers postgresql-dev
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./
EXPOSE 5000
CMD ["python", "app.py"]

