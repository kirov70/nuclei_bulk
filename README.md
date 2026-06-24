# 1. Create a virtual environment
python3 -m venv nuclei-env

# 2. Activate it
source nuclei-env/bin/activate

# 3. Upgrade pip and install the packages
pip install --upgrade pip
pip install pandas openpyxl

# 4. Now run your script using the venv python
python nuclei_orchestrator.py
python nuclei_html_generator
