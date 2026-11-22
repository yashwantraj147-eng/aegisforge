# Contributing to AegisForge

Thank you for your interest in contributing to **AegisForge**! We welcome contributions from security researchers, full-stack engineers, and open-source enthusiasts.

Before you begin, please review this guide to understand our development workflows, coding standards, and strict ethical safety guidelines.

---

## 1. Ethical Safety & Project Philosophy

AegisForge is designed exclusively for **educational, defensive, and purple-team research purposes**.
- **RFC 1918 / Localhost Only**: Under no circumstances will contributions that enable scanning, probing, or attacking external networks or public IP spaces be accepted.
- **Zero Real-World Malware**: All sample binaries, test payloads, and triage artifacts must be 100% benign, synthetic, or harmless standards (e.g., EICAR test string). No weaponized exploit payloads or live malware samples are permitted.
- **Defense-Oriented**: Every offensive discovery module must be paired with its corresponding defensive mitigation (e.g., ARP spoofing paired with Dynamic ARP Inspection, buffer overflow paired with Stack Canary/NX).

Please also read our [SECURITY.md](SECURITY.md) and [docs/ETHICAL_DISCLOSURE_GUIDE.md](docs/ETHICAL_DISCLOSURE_GUIDE.md).

---

## 2. Development Setup

### Prerequisites
- **Python**: 3.11, 3.12, or 3.13
- **Node.js**: v20+ or v22+ LTS (npm v10+)
- **Git**: Installed and configured
- **Docker** *(Optional)*: For containerized sandbox testing

### Step 1: Clone the Repository
```bash
git clone https://github.com/yashwantraj147-eng/aegisforge.git
cd aegisforge
```

### Step 2: Set Up Backend Environment
```bash
# Create and activate virtual environment
python -m venv venv

# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Linux / macOS:
# source venv/bin/activate

# Install backend dependencies in editable mode
pip install -e ./backend
pip install typer rich pytest pytest-asyncio pytest-cov ruff

# Copy development environment config
cp .env.example .env
```

### Step 3: Set Up Frontend Environment
```bash
cd frontend
npm install
cd ..
```

### Step 4: Generate Benign Test Artifacts
```bash
python sandbox/sample_artifacts/generate_benign_samples.py
```

---

## 3. Running Services Locally

### Running the FastAPI Backend
```bash
# From workspace root:
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```
- Interactive Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`
- Prometheus Metrics: `http://127.0.0.1:8000/metrics`

### Running the React Frontend
```bash
cd frontend
npm run dev
```
- Web Dashboard: `http://localhost:5173`

### Running the CLI Companion (`aegisctl`)
```bash
# Test health check
python cli/aegisctl.py health

# Run end-to-end purple-team demo
python cli/aegisctl.py demo
```

---

## 4. Testing & Quality Assurance

All PRs must pass the complete test suite and frontend production build.

### Running Backend Tests
```bash
# Run all tests with verbose output
python -m pytest backend/tests -v

# Run with test coverage report
python -m pytest backend/tests -v --cov=backend/app --cov-report=term-missing
```

### Verifying Frontend Build & Types
```bash
cd frontend
npm run build
cd ..
```

### Code Formatting & Linting
```bash
# Backend lint check (Ruff)
python -m ruff check backend/

# Backend auto-formatting
python -m ruff format backend/
```

---

## 5. Coding Standards

### Backend (Python / FastAPI)
- **Type Annotations**: All function signatures must include type hints.
- **Pydantic v2**: All API request and response data must use strictly validated Pydantic v2 models in `backend/app/models/schemas.py`.
- **Async First**: Use `async`/`await` for I/O-bound tasks. Use `asyncio.to_thread` for CPU-intensive or blocking operations.
- **SafetyGuard Enforcement**: Any engine taking a network target or file input must validate through `SafetyGuard`.

### Frontend (React / TypeScript / Tailwind CSS)
- **TypeScript Strict Mode**: No untyped `any` without explicit justification.
- **Tailwind CSS v4**: Use utility classes following the existing dark-mode cyberpunk/terminal aesthetic (`bg-slate-900`, `border-cyan-500/30`, etc.).
- **Component Modularity**: Keep components decoupled, testable, and reusable. Avoid inline `alert()` calls; use the toast notification system (`useToast`).

---

## 6. Git Workflow & Commit Guidelines

1. **Create a Topic Branch**:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```
2. **Follow Conventional Commits**:
   - `feat(recon): add banner grabbing for SSH service`
   - `fix(exploit): correct stack frame alignment on x86_64`
   - `docs(api): update CVSS 3.1 calculation examples`
   - `test(maltriage): add test case for high-entropy packed PE`
3. **Keep Commits Atomic**: Group related changes together with clear commit descriptions.

---

## 7. Submitting a Pull Request

1. Ensure all backend tests pass (`45/45 passed`).
2. Ensure frontend build succeeds (`npm run build`).
3. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
4. Open a Pull Request against `master`.
5. Fill out the **Pull Request Template** completely.
6. A maintainer will review your submission and provide feedback.

---

## 8. Reporting Security Issues

Please **do not** open public GitHub issues for security vulnerabilities in AegisForge. Review our [SECURITY.md](SECURITY.md) for instructions on confidential disclosure.
