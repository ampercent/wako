# Wako Forensics

## Project Overview
**Wako** is an advanced, end-to-end memory forensics analysis pipeline designed to investigate browser-based cybercrime. It specifically targets volatile memory dumps (`.dmp`) to extract critical artifacts such as running processes, network connections, opened URLs, domain history, and suspicious indicators (phishing, malware).

The project combines a powerful Python/FastAPI backend engine—which wraps standard CLI forensic tools like Volatility 3 and Bulk Extractor—with a modern, interactive React frontend dashboard for investigators.

---

## 🏗️ Architecture

- **Backend**: Python 3.10+, FastAPI, Uvicorn. Handles memory dump parsing, evidence extraction, and database management.
- **Frontend**: React 18, Vite, Tailwind CSS, Shadcn UI. Provides an interactive UI for exploring forensic cases, running queries, and analyzing indicators of compromise (IOCs).
- **Deployment**: Docker Compose for easy containerized setup.

---

## 🚀 Getting Started

You can run Wako either via **Docker (Recommended)** or **Manually** for development purposes.

### Prerequisites
Before running the application, make sure you have the following installed on your host machine:
* [Docker](https://docs.docker.com/get-docker/) & [Docker Compose](https://docs.docker.com/compose/install/) (for containerized deployment)
* **OR** [Node.js](https://nodejs.org/) (v18+) and [Python](https://www.python.org/) (3.10+) for manual setup.
* Git

### Step 1: Download the Source Code
```bash
git clone https://github.com/ampercent/wako.git
cd wako
```

### Step 2: Prepare the Environment
The application requires specific directories for tools and evidence. Ensure the following directories exist in the root of the project:
* `Evidence/` - Place your `.dmp` memory dump files here.
* `Tools/` - Forensic tools used by the backend (e.g., Volatility 3, Bulk Extractor).
* `Layer1_Output_Edge/` - Directory for pipeline outputs.

You may also want to copy the example environment file:
```bash
# On Linux/Mac:
cp .env.example .env

# On Windows PowerShell:
Copy-Item .env.example -Destination .env
```

---

### Option A: Running with Docker (Recommended)

This is the easiest way to run both the frontend and backend with all necessary dependencies.

1. **Build and start the containers in detached mode:**
   ```bash
   docker compose up -d --build
   ```
2. **Access the Application:**
   * **Frontend Dashboard**: Open your browser and navigate to `http://localhost` (or `http://localhost:80`).
   * **Backend API Documentation**: Open `http://localhost:8001/docs`.

3. **To stop the application:**
   ```bash
   docker compose down
   ```
   *(To view logs, run `docker compose logs -f`)*

---

### Option B: Running Manually (Development)

If you wish to run the components separately for development:

#### 1. Start the Backend (FastAPI)
```bash
# From the project root
python -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows PowerShell:
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the FastAPI server
uvicorn api:app --host 0.0.0.0 --port 8001 --reload
```

#### 2. Start the Frontend (React + Vite)
Open a new terminal window:
```bash
# Navigate to the frontend directory
cd frontend

# Install dependencies
npm install

# Start the development server
npm run dev
```
The frontend will typically be accessible at `http://localhost:5173`.

---

## 🔍 Methodology & Pipeline
Wako's backend executes a systematic pipeline:
1. **Memory Acquisition**: Extracting volatile memory into raw `.dmp` files.
2. **Process Analysis**: Identifying browser processes and suspicious scripts.
3. **Network Correlation**: Mapping process IDs to active TCP/UDP connections.
4. **Artifact Scraping**: Recovering URLs and domain names from unallocated space.

---

## ⚠️ Limitations & Notes
* **Processing Time**: Large memory dumps (32GB+) require significant processing time, especially for full network scans.
* **Encryption**: HTTPS traffic content cannot be fully decrypted without SSL keys; however, DNS/SNI artifacts remain visible in memory strings and are successfully parsed by Wako.
