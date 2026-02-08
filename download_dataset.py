"""
Download NSL-KDD Dataset
This script downloads the NSL-KDD dataset for training
"""

import os
import urllib.request
from utils import setup_logging
from config import DATA_DIR

logger = setup_logging(__name__)

# NSL-KDD dataset URLs
URLS = {
    'train': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt',
    'test': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt'
}

def download_file(url, filepath):
    """
    Download a file from URL
    
    Args:
        url: URL to download from
        filepath: Path to save the file
    """
    try:
        logger.info(f"Downloading {os.path.basename(filepath)}...")
        urllib.request.urlretrieve(url, filepath)
        logger.info(f"Downloaded to {filepath}")
        return True
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        return False

def download_nsl_kdd():
    """
    Download NSL-KDD dataset
    """
    logger.info("="*60)
    logger.info("DOWNLOADING NSL-KDD DATASET")
    logger.info("="*60)
    
    # Create data directory
    os.makedirs(DATA_DIR, exist_ok=True)
    
    # Download training data
    train_file = os.path.join(DATA_DIR, 'KDDTrain+.txt')
    if not os.path.exists(train_file):
        success = download_file(URLS['train'], train_file)
        if not success:
            logger.error("Failed to download training data")
            return False
    else:
        logger.info(f"Training data already exists: {train_file}")
    
    # Download test data
    test_file = os.path.join(DATA_DIR, 'KDDTest+.txt')
    if not os.path.exists(test_file):
        success = download_file(URLS['test'], test_file)
        if not success:
            logger.error("Failed to download test data")
            return False
    else:
        logger.info(f"Test data already exists: {test_file}")
    
    logger.info("="*60)
    logger.info("DATASET DOWNLOAD COMPLETE")
    logger.info("="*60)
    logger.info(f"Training data: {train_file}")
    logger.info(f"Test data: {test_file}")
    
    return True

if __name__ == "__main__":
    download_nsl_kdd()
