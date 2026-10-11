 
# 1. IMMAGINE BASE: Parte da una versione di Linux con Python 3.11 già pronto
FROM python:3.11-slim

# 2. CARTELLA DI LAVORO: Crea e si sposta nella cartella /app dentro il container
WORKDIR /app

# 3. DIPENDENZE: Copia il file dei requisiti e installa le librerie (Streamlit, ecc.)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. CODICE: Copia tutti i file del tuo PC (app.py, scanner.py) dentro la cartella /app del container
COPY . .

# 5. PORTA: Informa Docker che l'applicazione userà la porta 8501 (quella di Streamlit)
EXPOSE 8501

# 6. COMANDO DI AVVIO: Il comando automatico che parte quando il container si accende
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.fileWatcherType=poll"]