# 🛡️ Network Traffic Classification and Intrusion Detection System

A comprehensive Machine Learning-based Network Intrusion Detection System (NIDS) capable of analyzing both offline datasets and real-time network traffic. The system classifies traffic as normal or malicious and detects various cyber attacks including DoS, Probe, R2L, and U2R attacks.

## ✨ Features

- **Offline Analysis**: Train ML models on IDS datasets (NSL-KDD)
- **Real-time Detection**: Live packet capture and classification using Scapy
- **ML Models**: Random Forest & XGBoost classifiers with >90% accuracy
- **Web Dashboard**: Real-time monitoring interface with live updates
- **Alert System**: Automated attack detection and notifications
- **Performance Metrics**: Accuracy, Precision, Recall, F1-score, ROC curves

## 🎯 System Architecture

```
Network Traffic → Packet Capture → Feature Extraction → ML Classification → Alert System → Dashboard
```

## 📋 Requirements

- Python 3.8+
- Administrator/Root privileges (for packet capture)
- Windows/Linux/macOS

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Download NSL-KDD Dataset

Download the NSL-KDD dataset from: https://www.unb.ca/cic/datasets/nsl.html

Place the following files in the `data/` directory:
- `KDDTrain+.txt`
- `KDDTest+.txt`

### 3. Train Models

```bash
python train_models.py
```

This will:
- Load and preprocess the NSL-KDD dataset
- Train Random Forest and XGBoost models
- Generate evaluation metrics and visualizations
- Save the best model to `models/best_model.pkl`

### 4. Run the Dashboard

```bash
python app.py
```

The dashboard will be available at:
- **Local access**: http://localhost:5000
- **Remote access**: http://YOUR_IP_ADDRESS:5000

**Note**: For real-time packet capture, you need to run with administrator privileges.

## 📊 Performance Metrics

Expected performance on NSL-KDD dataset:

| Metric | Random Forest | XGBoost |
|--------|--------------|---------|
| Accuracy | >90% | >92% |
| Precision | >88% | >90% |
| Recall | >90% | >91% |
| F1-Score | >89% | >90% |

## 🔧 Usage

### Offline Analysis

Analyze a dataset without real-time capture:

```bash
python analyze_offline.py --model models/best_model.pkl --dataset data/test.csv
```

### Real-time Detection

Start real-time network monitoring (requires admin privileges):

```bash
# Windows (run as Administrator)
python run_realtime.py

# Linux/macOS (run with sudo)
sudo python run_realtime.py
```

### Web Dashboard

The dashboard provides:
- Real-time traffic monitoring
- Attack detection alerts
- Traffic statistics and charts
- Model performance metrics

## 📁 Project Structure

```
.
├── app.py                      # Flask web application
├── config.py                   # Configuration settings
├── utils.py                    # Utility functions
├── data_handler.py             # Dataset loading and preprocessing
├── feature_extractor.py        # Feature extraction from packets
├── packet_capture.py           # Real-time packet capture
├── alert_system.py             # Alert management
├── intrusion_detector.py       # Real-time detection engine
├── evaluator.py                # Model evaluation
├── train_models.py             # Model training script
├── models/
│   ├── random_forest_model.py  # Random Forest classifier
│   └── xgboost_model.py        # XGBoost classifier
├── templates/
│   └── index.html              # Dashboard HTML
├── static/
│   ├── css/style.css           # Dashboard styling
│   └── js/dashboard.js         # Dashboard JavaScript
├── data/                       # Dataset directory
├── models/                     # Trained models
├── logs/                       # System logs
└── results/                    # Evaluation results
```

## 🌐 Remote Access

The dashboard is configured for remote access. To access from another device:

1. Find your IP address:
   ```bash
   # Windows
   ipconfig
   
   # Linux/macOS
   ifconfig
   ```

2. Access the dashboard from any device on the same network:
   ```
   http://YOUR_IP_ADDRESS:5000
   ```

3. **Firewall Configuration**: Ensure port 5000 is open in your firewall.

## 🔒 Security Notes

- The system requires administrator/root privileges for packet capture
- The dashboard is accessible from any IP on the network (0.0.0.0)
- For production use, implement authentication and HTTPS
- Consider firewall rules to restrict access

## 📝 Attack Categories

The system detects the following attack types:

- **DoS (Denial of Service)**: back, land, neptune, pod, smurf, teardrop
- **Probe (Scanning)**: satan, ipsweep, nmap, portsweep
- **R2L (Remote to Local)**: guess_passwd, ftp_write, imap, phf, multihop
- **U2R (User to Root)**: buffer_overflow, loadmodule, rootkit, perl

## 🛠️ Troubleshooting

### Model Not Found Error
```
Solution: Run python train_models.py first to train the models
```

### Permission Denied (Packet Capture)
```
Solution: Run with administrator/root privileges
Windows: Run as Administrator
Linux/macOS: Use sudo
```

### Dataset Not Found
```
Solution: Download NSL-KDD dataset and place in data/ directory
```

## 📚 References

- NSL-KDD Dataset: https://www.unb.ca/cic/datasets/nsl.html
- Scapy Documentation: https://scapy.net/
- Flask Documentation: https://flask.palletsprojects.com/

## 👨‍💻 Author

Network Intrusion Detection System - ML-based Traffic Classification

## 📄 License

This project is for educational and research purposes.
