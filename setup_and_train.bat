@echo off
echo ========================================
echo Network Intrusion Detection System
echo ========================================
echo.

echo Step 1: Installing Dependencies...
python -m pip install scikit-learn xgboost pandas numpy flask flask-socketio flask-cors matplotlib seaborn scapy imbalanced-learn joblib tqdm python-dotenv eventlet scipy lightgbm
echo.

echo Step 2: Downloading NSL-KDD Dataset...
python download_dataset.py
echo.

echo Step 3: Training ML Models...
echo This may take several minutes...
python train_models.py
echo.

echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo To start the dashboard, run:
echo   python app.py
echo.
echo Dashboard will be available at:
echo   Local: http://localhost:5000
echo   Remote: http://YOUR_IP_ADDRESS:5000
echo.
pause
