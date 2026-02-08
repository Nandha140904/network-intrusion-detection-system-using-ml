# Network Traffic Classification and Intrusion Detection Using Machine Learning

## Abstract

With the rapid growth of internet usage, networks are increasingly vulnerable to cyber attacks such as Denial of Service, brute force, and malware intrusions. Traditional rule-based intrusion detection systems are ineffective against evolving attack patterns. This project proposes a Machine Learning-based Network Traffic Classification and Intrusion Detection System capable of analyzing both offline datasets and real-time network traffic.

The system extracts meaningful features from network packets and applies supervised learning algorithms such as Random Forest and XGBoost to classify traffic as normal or malicious. The feature extraction module processes packet-level and flow-based characteristics including packet size, duration, protocol information, and statistical metrics compatible with the NSL-KDD dataset format.

Two ensemble learning models were implemented and compared: Random Forest and XGBoost classifiers. Both models were trained on the NSL-KDD dataset with comprehensive preprocessing including categorical encoding, feature scaling, and class balancing using SMOTE. Cross-validation was employed to ensure model generalization and prevent overfitting.

Experimental results demonstrate improved detection accuracy and reduced false positives compared to traditional approaches. The Random Forest model achieved over 90% accuracy with high precision and recall across all attack categories. The XGBoost model showed even better performance with over 92% accuracy and superior handling of minority attack classes.

The proposed system enhances network security by enabling early detection and real-time monitoring of cyber threats through a web-based dashboard. The dashboard provides real-time traffic visualization, attack alerts, and comprehensive performance metrics. The system successfully classifies network traffic into five categories: normal, DoS (Denial of Service), Probe (scanning), R2L (Remote to Local), and U2R (User to Root) attacks.

Key contributions of this work include:
1. A comprehensive feature extraction framework for real-time packet analysis
2. Comparative evaluation of ensemble learning algorithms for intrusion detection
3. Real-time detection engine with live packet capture capabilities
4. Interactive web dashboard for network security monitoring
5. Automated alert system for immediate threat notification

The system demonstrates the effectiveness of machine learning approaches in network intrusion detection and provides a practical solution for real-world network security applications. Future work may include deep learning models, additional attack categories, and distributed deployment for large-scale networks.

## Keywords

Network Security, Intrusion Detection, Machine Learning, Random Forest, XGBoost, Traffic Classification, Real-time Monitoring, NSL-KDD Dataset, Cyber Attack Detection, Ensemble Learning
