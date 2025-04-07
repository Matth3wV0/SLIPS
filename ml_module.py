#!/usr/bin/env python3
"""
Machine Learning module for Suricata JSON analysis
"""
import os
import numpy as np
import pandas as pd
import pickle
from typing import Dict, List, Tuple, Union, Any, Optional
import logging
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import joblib

# Local imports
from feature_extraction import FeatureExtractor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ml_module')


class MLModel:
    """Machine Learning model for network traffic analysis"""
    
    def __init__(self, model_dir: str = 'models'):
        """
        Initialize the ML model
        
        Args:
            model_dir: Directory to save/load models
        """
        self.model_dir = model_dir
        self.feature_extractor = FeatureExtractor()
        self.supervised_model = None  # For classification (labeled data)
        self.anomaly_model = None     # For anomaly detection (unlabeled data)
        self.scaler = StandardScaler()
        
        # Create model directory if it doesn't exist
        os.makedirs(model_dir, exist_ok=True)
        
    def prepare_dataset(self, file_paths: List[str], labeled: bool = False) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prepare dataset from multiple Suricata JSON files
        
        Args:
            file_paths: List of paths to Suricata JSON files
            labeled: Whether the dataset contains labeled data
            
        Returns:
            Tuple of (X, y) where X is features and y is labels (or None if unlabeled)
        """
        all_features = []
        all_labels = []
        
        for file_path in file_paths:
            logger.info(f"Processing file: {file_path}")
            
            # Extract features
            df = self.feature_extractor.process_file(file_path)
            
            # Skip if no features were extracted
            if df.empty:
                logger.warning(f"No features extracted from {file_path}")
                continue
                
            # Handle labels if available
            if labeled:
                # For labeled data, we expect a 'has_alert' column or similar
                # This could be modified based on your specific dataset structure
                if 'has_alert' in df.columns:
                    labels = df['has_alert'].values
                else:
                    # If the label column is missing, assume all normal (0)
                    logger.warning(f"No 'has_alert' column found in {file_path}, assuming all normal")
                    labels = np.zeros(len(df))
                    
                all_labels.append(labels)
                
            # Drop identifier columns for ML
            feature_df = df.drop(columns=['uid'], errors='ignore')
            
            # Get feature vectors
            feature_vectors = self.feature_extractor.get_feature_vector(feature_df)
            all_features.append(feature_vectors)
            
        if not all_features:
            logger.error("No features extracted from any files")
            return np.array([]), np.array([])
            
        # Combine features from all files
        X = np.vstack(all_features)
        
        if labeled and all_labels:
            y = np.hstack(all_labels)
            return X, y
        else:
            return X, None
    
    def train_supervised_model(self, X: np.ndarray, y: np.ndarray) -> None:
        """
        Train a supervised classification model
        
        Args:
            X: Feature matrix
            y: Target labels
        """
        logger.info(f"Training supervised model on {X.shape[0]} samples")
        
        # Split data into training and validation sets
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        # Initialize and train the model
        self.supervised_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=None,
            min_samples_split=2,
            min_samples_leaf=1,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        
        self.supervised_model.fit(X_train, y_train)
        
        # Evaluate the model
        y_pred = self.supervised_model.predict(X_val)
        accuracy = accuracy_score(y_val, y_pred)
        
        logger.info(f"Model trained with validation accuracy: {accuracy:.4f}")
        logger.info("\nClassification Report:\n" + 
                   classification_report(y_val, y_pred))
        
        # Save the model
        model_path = os.path.join(self.model_dir, 'supervised_model.pkl')
        joblib.dump(self.supervised_model, model_path)
        logger.info(f"Model saved to {model_path}")
        
    def train_anomaly_model(self, X: np.ndarray) -> None:
        """
        Train an unsupervised anomaly detection model
        
        Args:
            X: Feature matrix
        """
        logger.info(f"Training anomaly detection model on {X.shape[0]} samples")
        
        # Initialize and train the model
        self.anomaly_model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=0.01,  # Assuming 1% anomalies
            random_state=42,
            n_jobs=-1
        )
        
        self.anomaly_model.fit(X)
        
        # Save the model
        model_path = os.path.join(self.model_dir, 'anomaly_model.pkl')
        joblib.dump(self.anomaly_model, model_path)
        logger.info(f"Model saved to {model_path}")
        
    def load_models(self) -> None:
        """Load saved models from disk"""
        supervised_path = os.path.join(self.model_dir, 'supervised_model.pkl')
        anomaly_path = os.path.join(self.model_dir, 'anomaly_model.pkl')
        
        if os.path.exists(supervised_path):
            logger.info(f"Loading supervised model from {supervised_path}")
            self.supervised_model = joblib.load(supervised_path)
        else:
            logger.warning(f"Supervised model not found at {supervised_path}")
            
        if os.path.exists(anomaly_path):
            logger.info(f"Loading anomaly model from {anomaly_path}")
            self.anomaly_model = joblib.load(anomaly_path)
        else:
            logger.warning(f"Anomaly model not found at {anomaly_path}")
    
    def predict(self, features: np.ndarray) -> Dict[str, Any]:
        """
        Make predictions using trained models
        
        Args:
            features: Feature matrix
            
        Returns:
            Dictionary with prediction results
        """
        results = {
            'supervised': None,
            'anomaly': None,
            'combined': None
        }
        
        # Supervised prediction (if model is available)
        if self.supervised_model:
            try:
                y_pred = self.supervised_model.predict(features)
                y_prob = self.supervised_model.predict_proba(features)
                
                results['supervised'] = {
                    'prediction': y_pred,
                    'probability': y_prob
                }
            except Exception as e:
                logger.error(f"Error in supervised prediction: {e}")
                
        # Anomaly detection (if model is available)
        if self.anomaly_model:
            try:
                # predict_proba not available for IsolationForest, use decision_function
                scores = self.anomaly_model.decision_function(features)
                y_pred = self.anomaly_model.predict(features)
                
                # Convert -1/1 to 1/0 (anomaly/normal)
                y_pred = np.where(y_pred == -1, 1, 0)
                
                results['anomaly'] = {
                    'prediction': y_pred,
                    'scores': scores
                }
            except Exception as e:
                logger.error(f"Error in anomaly detection: {e}")
                
        # Combine predictions if both models are available
        if results['supervised'] is not None and results['anomaly'] is not None:
            # Combine by taking maximum of supervised and anomaly
            combined = np.maximum(
                results['supervised']['prediction'],
                results['anomaly']['prediction']
            )
            
            results['combined'] = combined
            
        return results
    
    def analyze_file(self, file_path: str) -> pd.DataFrame:
        """
        Analyze a Suricata JSON file and return detection results
        
        Args:
            file_path: Path to the Suricata JSON file
            
        Returns:
            DataFrame with features and detection results
        """
        # Load models if not loaded yet
        if not self.supervised_model or not self.anomaly_model:
            self.load_models()
            
        # Extract features
        df = self.feature_extractor.process_file(file_path)
        
        # Skip if no features were extracted
        if df.empty:
            logger.warning(f"No features extracted from {file_path}")
            return pd.DataFrame()
            
        # Get flow identifiers
        flow_ids = df['uid'].values
        
        # Drop identifier columns for ML
        feature_df = df.drop(columns=['uid'], errors='ignore')
        
        # Get feature vectors
        feature_vectors = self.feature_extractor.get_feature_vector(feature_df)
        
        # Make predictions
        results = self.predict(feature_vectors)
        
        # Add predictions to DataFrame
        result_df = pd.DataFrame({'uid': flow_ids})
        
        if results['supervised'] is not None:
            result_df['supervised_prediction'] = results['supervised']['prediction']
            result_df['supervised_probability'] = np.max(results['supervised']['probability'], axis=1)
            
        if results['anomaly'] is not None:
            result_df['anomaly_prediction'] = results['anomaly']['prediction']
            result_df['anomaly_score'] = results['anomaly']['scores']
            
        if results['combined'] is not None:
            result_df['combined_prediction'] = results['combined']
            
        # Merge with original features
        result_df = pd.merge(df, result_df, on='uid')
        
        return result_df


class ModelTrainer:
    """Class for training and evaluating ML models"""
    
    def __init__(self, data_dir: str = 'data', model_dir: str = 'models'):
        """
        Initialize the model trainer
        
        Args:
            data_dir: Directory containing training data
            model_dir: Directory to save models
        """
        self.data_dir = data_dir
        self.model_dir = model_dir
        self.ml_model = MLModel(model_dir)
        
    def prepare_training_data(self, normal_dir: str = None, attack_dir: str = None) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prepare training data from directories of normal and attack traffic
        
        Args:
            normal_dir: Directory containing normal traffic files
            attack_dir: Directory containing attack traffic files
            
        Returns:
            Tuple of (X, y) where X is features and y is labels
        """
        # Use default directories if not specified
        if normal_dir is None:
            normal_dir = os.path.join(self.data_dir, 'normal')
        if attack_dir is None:
            attack_dir = os.path.join(self.data_dir, 'attack')
            
        # Check if directories exist
        if not os.path.exists(normal_dir):
            logger.error(f"Normal traffic directory not found: {normal_dir}")
            return np.array([]), np.array([])
            
        if not os.path.exists(attack_dir):
            logger.error(f"Attack traffic directory not found: {attack_dir}")
            return np.array([]), np.array([])
            
        # Get file paths
        normal_files = [os.path.join(normal_dir, f) for f in os.listdir(normal_dir) 
                      if f.endswith('.json') or f.endswith('.eve')]
        attack_files = [os.path.join(attack_dir, f) for f in os.listdir(attack_dir) 
                       if f.endswith('.json') or f.endswith('.eve')]
        
        logger.info(f"Found {len(normal_files)} normal traffic files and {len(attack_files)} attack traffic files")
        
        # Process normal traffic files
        normal_features = []
        for file_path in normal_files:
            logger.info(f"Processing normal traffic file: {file_path}")
            df = self.ml_model.feature_extractor.process_file(file_path)
            
            if not df.empty:
                # Drop identifier columns
                feature_df = df.drop(columns=['uid'], errors='ignore')
                
                # Get feature vectors
                feature_vectors = self.ml_model.feature_extractor.get_feature_vector(feature_df)
                normal_features.append(feature_vectors)
                
        # Process attack traffic files
        attack_features = []
        for file_path in attack_files:
            logger.info(f"Processing attack traffic file: {file_path}")
            df = self.ml_model.feature_extractor.process_file(file_path)
            
            if not df.empty:
                # Drop identifier columns
                feature_df = df.drop(columns=['uid'], errors='ignore')
                
                # Get feature vectors
                feature_vectors = self.ml_model.feature_extractor.get_feature_vector(feature_df)
                attack_features.append(feature_vectors)
                
        # Combine features and create labels
        if normal_features and attack_features:
            X_normal = np.vstack(normal_features)
            y_normal = np.zeros(X_normal.shape[0])
            
            X_attack = np.vstack(attack_features)
            y_attack = np.ones(X_attack.shape[0])
            
            X = np.vstack([X_normal, X_attack])
            y = np.hstack([y_normal, y_attack])
            
            logger.info(f"Prepared dataset with {X.shape[0]} samples ({X_normal.shape[0]} normal, {X_attack.shape[0]} attack)")
            
            return X, y
        else:
            logger.error("Failed to extract features from training data")
            return np.array([]), np.array([])
    
    def train_models(self, X: np.ndarray, y: np.ndarray) -> None:
        """
        Train supervised and anomaly detection models
        
        Args:
            X: Feature matrix
            y: Target labels
        """
        # Train supervised model
        self.ml_model.train_supervised_model(X, y)
        
        # Train anomaly detection model (using only normal traffic for training)
        X_normal = X[y == 0]
        self.ml_model.train_anomaly_model(X_normal)
        
    def train_from_directories(self, normal_dir: str = None, attack_dir: str = None) -> None:
        """
        Train models from directories of normal and attack traffic
        
        Args:
            normal_dir: Directory containing normal traffic files
            attack_dir: Directory containing attack traffic files
        """
        # Prepare training data
        X, y = self.prepare_training_data(normal_dir, attack_dir)
        
        if X.size > 0 and y.size > 0:
            # Train models
            self.train_models(X, y)
        else:
            logger.error("Failed to prepare training data")
            
    def evaluate_model(self, test_dir: str = None) -> Dict[str, Any]:
        """
        Evaluate trained models on test data
        
        Args:
            test_dir: Directory containing test data
            
        Returns:
            Dictionary with evaluation results
        """
        # Use default directory if not specified
        if test_dir is None:
            test_dir = os.path.join(self.data_dir, 'test')
            
        # Check if directory exists
        if not os.path.exists(test_dir):
            logger.error(f"Test directory not found: {test_dir}")
            return {}
            
        # Get file paths
        test_files = [os.path.join(test_dir, f) for f in os.listdir(test_dir) 
                     if f.endswith('.json') or f.endswith('.eve')]
        
        logger.info(f"Found {len(test_files)} test files")
        
        # Load models
        self.ml_model.load_models()
        
        all_results = {
            'supervised': {
                'true': [],
                'pred': []
            },
            'anomaly': {
                'true': [],
                'pred': []
            },
            'combined': {
                'true': [],
                'pred': []
            }
        }
        
        # Process test files
        for file_path in test_files:
            logger.info(f"Evaluating on test file: {file_path}")
            
            # Ground truth (assuming filenames contain 'normal' or 'attack')
            is_attack = 'attack' in os.path.basename(file_path).lower()
            true_label = 1 if is_attack else 0
            
            # Analyze file
            result_df = self.ml_model.analyze_file(file_path)
            
            if result_df.empty:
                continue
                
            # Collect supervised results
            if 'supervised_prediction' in result_df.columns:
                all_results['supervised']['true'].extend([true_label] * len(result_df))
                all_results['supervised']['pred'].extend(result_df['supervised_prediction'].tolist())
                
            # Collect anomaly results
            if 'anomaly_prediction' in result_df.columns:
                all_results['anomaly']['true'].extend([true_label] * len(result_df))
                all_results['anomaly']['pred'].extend(result_df['anomaly_prediction'].tolist())
                
            # Collect combined results
            if 'combined_prediction' in result_df.columns:
                all_results['combined']['true'].extend([true_label] * len(result_df))
                all_results['combined']['pred'].extend(result_df['combined_prediction'].tolist())
                
        # Calculate evaluation metrics
        evaluation = {}
        
        for model_type in ['supervised', 'anomaly', 'combined']:
            if all_results[model_type]['true'] and all_results[model_type]['pred']:
                y_true = np.array(all_results[model_type]['true'])
                y_pred = np.array(all_results[model_type]['pred'])
                
                evaluation[model_type] = {
                    'accuracy': accuracy_score(y_true, y_pred),
                    'report': classification_report(y_true, y_pred, output_dict=True),
                    'confusion_matrix': confusion_matrix(y_true, y_pred).tolist()
                }
                
        logger.info(f"Evaluation complete: {evaluation}")
        return evaluation


# Example usage
if __name__ == "__main__":
    # Training example
    trainer = ModelTrainer(data_dir='data', model_dir='models')
    trainer.train_from_directories()
    
    # Evaluation example
    eval_results = trainer.evaluate_model()
    
    # Analysis example
    ml_model = MLModel('models')
    results_df = ml_model.analyze_file('example.json')
    print(f"Analyzed file with {len(results_df)} flows")
