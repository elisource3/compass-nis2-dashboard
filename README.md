\# COMPASS — NIS2 Security \& Risk Assessment Dashboard



\*\*COMPASS\*\* è una dashboard interattiva Enterprise-grade sviluppata in Streamlit, progettata per la valutazione, il monitoraggio e la reportistica della conformità alla \*\*Direttiva UE 2022/2555 (NIS2)\*\*, con particolare focus sui requisiti dell'Articolo 21 (misure di gestione dei rischi di cibersicurezza).



Il sistema unisce l'analisi tecnica automatica degli endpoint (tramite scanner di sistema) a valutazioni di governance procedurale e umana, calcolando un punteggio di sicurezza combinato e una matrice di rischio dinamica.



\---



\## Security \& Hardening by Design

COMPASS è stata progettata seguendo rigorosi principi di sicurezza e robustezza (NIS2 compliance):

\* \*\*Prevenzione XSS:\*\* Sanitizzazione rigorosa di tutti gli input dinamici e dei dati dei report tramite `html.escape()`.

\* \*\*Mitigazione DoS:\*\* Controllo rigoroso della dimensione massima dei file JSON caricati (limite massimo impostato a 5 MB).

\* \*\*Protezione CSRF \& Configurazione Server:\*\* Configurazione dedicata in `.streamlit/config.toml` con protezione XSRF attiva e disattivazione della telemetria.

\* \*\*Integrità del Codice:\*\* Architettura pulita, priva di ridondanze e con robusta gestione delle eccezioni per il parsing dei dati.



\---



## Nota Importante: Modalità Demo vs Scansione Reale

Per testare o utilizzare COMPASS, puoi scegliere tra due modalità operative:

### 1. Modalità Demo (Consigliata per una prova rapida)
* **Requisiti:** Solo [Docker Desktop](https://www.docker.com/) e Docker Compose.
* **Python sul PC locale:** **Non necessario.** (L'interprete Python e le librerie necessarie sono già inclusi e isolati all'interno dell'immagine Docker).
* **Come funziona:** Avviando il container, la dashboard caricherà un file di esempio (`sample_report.json`) già presente nel repository. Questo ti permette di esplorare immediatamente l'intera interfaccia grafica, i grafici a radar e le guide di remediation senza configurare nulla sul tuo sistema.

### 2. Modalità Audit Reale (Esecuzione dello Scanner)
Se desideri effettuare un'analisi tecnica reale della tua macchina per generare un report di conformità personalizzato:
* **Python sul PC locale:** **Necessario.**
* **Perché non eseguire lo scanner dentro Docker?** 
  Eseguire lo script `scanner.py` all'interno del container Docker **non è corretto né consigliato**: il container gira su un ambiente Linux isolato (tramite WSL o motore Docker), quindi lo scanner analizzerebbe soltanto le impostazioni di quel minuscolo sistema virtuale, **e non il tuo vero sistema operativo host (es. Windows)**.

---

## Guida all'Avvio (Deployment con Docker)

### Prerequisiti
- [Docker](https://www.docker.com/) e [Docker Compose](https://docs.docker.com/compose/) installati sul sistema.

### Passaggi per l'esecuzione rapida (Modalità Demo):

1. **Clona il Repository e accedi alla cartella:**
   ```bash
   git clone [https://github.com/elisource3/compass-nis2-dashboard.git](https://github.com/elisource3/compass-nis2-dashboard.git)
   cd compass-nis2-dashboard/COMPASS_NIS2_SCANNER

cd compass-nis2-dashboard\COMPASS_NIS2_SCANNER

