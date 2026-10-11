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



\##  Guida all'Avvio (Deployment con Docker)



Il modo più rapido e sicuro per eseguire COMPASS in un ambiente di produzione isolato è l'utilizzo di \*\*Docker\*\*.



\### Prerequisiti

\* \[Docker](https://www.docker.com/) e \[Docker Compose](https://docs.docker.com/compose/) installati sul sistema.



\### 1. Clona il Repository

```bash

git clone \[https://github.com/tuo-username/compass-nis2-dashboard.git](https://github.com/tuo-username/compass-nis2-dashboard.git)

cd compass-nis2-dashboard

