# VulnHGNN

VulnHGNN is a tool built to help detect, localize, and fix software vulnerabilities using Graph Neural Networks (GNNs). It comes with a web UI for when you want an interactive visual experience, as well as a command-line interface (CLI) for running automated pipelines. As a bonus, it also tracks the carbon emissions from running the models.

## What it does
- Detects vulnerabilities automatically using PyTorch Geometric and GNNs.
- Supports multi-label classification, meaning it can detect multiple types of vulnerabilities at once.
- Localizes exactly where the vulnerability is in your code.
- Features self-healing capabilities to automatically suggest and apply fixes.
- Checks C syntax and supported vulnerability patterns while you type in the web editor, with secure-coding guidance for detected issues.
- Provides an interactive web UI built with Flask to easily visualize and fix issues.
- Includes a full CLI pipeline to process source files and generate reports from your terminal.
- Tracks carbon emissions using CodeCarbon to measure the environmental impact of your ML workloads.

## What you need
Make sure you have Python 3.8 or newer installed. You'll also need Windows since we use `.bat` scripts for the launchers.

## How to set it up
1. Clone or download this repository to your machine.
2. Open your terminal or command prompt in the project folder.
3. Create a virtual environment by running `python -m venv venv`.
4. Activate the environment with `venv\Scripts\activate`.
5. Install everything you need by running `pip install -r requirements.txt`.

## Getting started

### Running the Web UI
The easiest way to use VulnHGNN is through the web app. Just double-click the `run.bat` file in the project folder, or run `run.bat` from your command prompt. It will automatically activate your environment and start the Flask server. Once it's running, open your browser and go to http://127.0.0.1:5000.

If you prefer doing it manually, you can activate your environment, navigate to the `src` folder, and run `python app.py`.

### Optional LLM Security Review
The local GNN analysis works without an LLM. To enable the optional review, configure an OpenAI-compatible chat-completions provider on the server before starting Flask:

```powershell
$env:VULNHGNN_LLM_API_KEY = "<provider API key>"
$env:VULNHGNN_LLM_MODEL = "<provider model name>"
# Optional; defaults to the OpenAI chat-completions endpoint.
$env:VULNHGNN_LLM_API_URL = "https://api.openai.com/v1/chat/completions"
python src/app.py
```

In the UI, check **Optional LLM review** to consent to sending the source to that provider. It is unchecked by default, and source over 64 KB is not sent. The provider returns a separate advisory score and findings; it does not control or apply repairs. Review the provider's data-handling policy before sending code.

### Live editor checks
After a short pause in typing, the web editor compiles the selected C or C++ source with Clang. To avoid false alarms, live security findings are shown only for constant division-by-zero cases Clang can directly confirm; GNN predictions are not shown in the live panel. Other vulnerability types are not confirmed by this live check. Live checks do not send code to an LLM provider and do not modify the source. A clean live check does not prove that code is secure. The separate Analyze action still uses the GNN to estimate supported patterns. Install Clang to use live syntax validation and constant division-by-zero checks.

### Running the CLI
If you want to process files directly from the command line, you can use the `run_pipeline.bat` script. By default, it runs a test file against our pre-trained model. 

To run it on your own files, you can manually run the pipeline like this:
1. Activate your virtual environment.
2. Set your python path: `set PYTHONPATH=%PYTHONPATH%;%CD%\src`
3. Run the script: `python src\pipeline.py path\to\your_file.c --no-carbon --model results\pyg_gnn_v9\best_pyg_model.pt`

## Folder structure

## Architecture
See [docs/architecture.md](docs/architecture.md) for the end-to-end architecture, runtime flow, security controls, and bounded self-healing agent cycle.
Open the [updated architecture diagram PNG](docs/vulnhgnn_full_architecture_with_llm_review.png) directly for presentations.
