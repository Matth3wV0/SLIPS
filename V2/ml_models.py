# models/unsupervised.py

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import pickle
import tensorflow as tf
from tensorflow.keras.layers import Input, Dense, Lambda
from tensorflow.keras.models import Model
import tensorflow.keras.backend as K

class VAEAnomalyDetector:
    """
    Variational Autoencoder for anomaly detection, inspired by SLIPS
    """
    
    def __init__(self, input_dim, latent_dim=10, hidden_layers=[64, 32]):
        """
        Initialize the VAE anomaly detector
        
        Args:
            input_dim (int): Input dimension
            latent_dim (int): Latent space dimension
            hidden_layers (list): Sizes of hidden layers
        """
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.hidden_layers = hidden_layers
        self.scaler = StandardScaler()
        self.model = None
        self.encoder = None
        self.decoder = None
        self.threshold = None
        
    def _build_model(self):
        """Build the VAE model architecture"""
        # Encoder
        inputs = Input(shape=(self.input_dim,), name='encoder_input')
        x = inputs
        
        for i, units in enumerate(self.hidden_layers):
            x = Dense(units, activation='relu', name=f'encoder_dense_{i}')(x)
        
        # Mean and log variance for latent space
        z_mean = Dense(self.latent_dim, name='z_mean')(x)
        z_log_var = Dense(self.latent_dim, name='z_log_var')(x)
        
        # Sampling function
        def sampling(args):
            z_mean, z_log_var = args
            batch = K.shape(z_mean)[0]
            dim = K.shape(z_mean)[1]
            epsilon = K.random_normal(shape=(batch, dim))
            return z_mean + K.exp(0.5 * z_log_var) * epsilon
        
        # Sample from latent space
        z = Lambda(sampling, output_shape=(self.latent_dim,), name='z')([z_mean, z_log_var])
        
        # Build encoder model
        self.encoder = Model(inputs, [z_mean, z_log_var, z], name='encoder')
        
        # Decoder
        latent_inputs = Input(shape=(self.latent_dim,), name='decoder_input')
        x = latent_inputs
        
        for i, units in enumerate(reversed(self.hidden_layers)):
            x = Dense(units, activation='relu', name=f'decoder_dense_{i}')(x)
        
        outputs = Dense(self.input_dim, activation='sigmoid', name='decoder_output')(x)
        
        # Build decoder model
        self.decoder = Model(latent_inputs, outputs, name='decoder')
        
        # VAE model
        outputs = self.decoder(self.encoder(inputs)[2])
        self.model = Model(inputs, outputs, name='vae')
        
        # Add KL divergence regularization
        reconstruction_loss = tf.keras.losses.mean_squared_error(inputs, outputs)
        reconstruction_loss *= self.input_dim
        kl_loss = -0.5 * K.sum(1 + z_log_var - K.square(z_mean) - K.exp(z_log_var), axis=-1)
        vae_loss = K.mean(reconstruction_loss + kl_loss)
        
        self.model.add_loss(vae_loss)
        self.model.compile(optimizer='adam')
        
    def fit(self, X, validation_split=0.1, batch_size=32, epochs=50):
        """
        Fit the VAE model
        
        Args:
            X (pd.DataFrame or np.array): Training data
            validation_split (float): Portion of data for validation
            batch_size (int): Batch size for training
            epochs (int): Number of training epochs
        """
        # Scale the data
        X_scaled = self.scaler.fit_transform(X)
        
        # Build the model if not already built
        if self.model is None:
            self._build_model()
        
        # Train the model
        self.model.fit(
            X_scaled, 
            epochs=epochs, 
            batch_size=batch_size, 
            validation_split=validation_split,
            verbose=1
        )
        
        # Determine the threshold for anomaly detection
        # Use reconstruction error on validation data (assuming mostly normal)
        val_data = X_scaled[-int(len(X_scaled) * validation_split):]
        reconstructions = self.model.predict(val_data)
        mse = np.mean(np.square(val_data - reconstructions), axis=1)
        
        # Set threshold at 95th percentile
        self.threshold = np.percentile(mse, 95)
        
    def predict(self, X):
        """
        Predict anomalies (1 for normal, -1 for anomaly)
        
        Args:
            X (pd.DataFrame or np.array): Data to predict
            
        Returns:
            np.array: Predictions (1=normal, -1=anomaly)
        """
        X_scaled = self.scaler.transform(X)
        reconstructions = self.model.predict(X_scaled)
        mse = np.mean(np.square(X_scaled - reconstructions), axis=1)
        
        return np.where(mse > self.threshold, -1, 1)
    
    def decision_function(self, X):
        """
        Calculate anomaly scores (higher = more anomalous)
        
        Args:
            X (pd.DataFrame or np.array): Data to score
            
        Returns:
            np.array: Anomaly scores
        """
        X_scaled = self.scaler.transform(X)
        reconstructions = self.model.predict(X_scaled)
        mse = np.mean(np.square(X_scaled - reconstructions), axis=1)
        
        # Normalize to 0-1 range
        min_val = np.min(mse)
        max_val = np.max(mse)
        if max_val > min_val:
            normalized_scores = (mse - min_val) / (max_val - min_val)
        else:
            normalized_scores = np.zeros_like(mse)
        
        return normalized_scores
    
    def save(self, filepath):
        """Save the model to disk"""
        # Save encoder and decoder weights
        self.encoder.save_weights(f"{filepath}_encoder.h5")
        self.decoder.save_weights(f"{filepath}_decoder.h5")
        
        # Save other components that can't be saved with Keras
        with open(f"{filepath}_metadata.pkl", 'wb') as f:
            pickle.dump({
                'input_dim': self.input_dim,
                'latent_dim': self.latent_dim,
                'hidden_layers': self.hidden_layers,
                'scaler': self.scaler,
                'threshold': self.threshold
            }, f)
            
    @classmethod
    def load(cls, filepath):
        """Load a saved model"""
        # Load metadata
        with open(f"{filepath}_metadata.pkl", 'rb') as f:
            metadata = pickle.load(f)
        
        # Create a new instance with the saved parameters
        instance = cls(
            input_dim=metadata['input_dim'],
            latent_dim=metadata['latent_dim'],
            hidden_layers=metadata['hidden_layers']
        )
        
        # Build the model
        instance._build_model()
        
        # Load weights
        instance.encoder.load_weights(f"{filepath}_encoder.h5")
        instance.decoder.load_weights(f"{filepath}_decoder.h5")
        
        # Set the rest of the attributes
        instance.scaler = metadata['scaler']
        instance.threshold = metadata['threshold']
        
        return instance

class IsolationForestDetector:
    """
    Anomaly detection using Isolation Forest
    """
    
    def __init__(self, contamination=0.01):
        """
        Initialize the anomaly detector
        
        Args:
            contamination (float): Expected proportion of outliers in the data
        """
        self.model = None
        self.scaler = StandardScaler()
        self.pca = None
        self.contamination = contamination
        self.feature_columns = None
    
    def fit(self, X, use_pca=True, n_components=0.95):
        """
        Fit the anomaly detection model
        
        Args:
            X (pd.DataFrame): Feature dataframe
            use_pca (bool): Whether to use PCA for dimensionality reduction
            n_components (float or int): Number of components or explained variance ratio
        """
        # Store feature columns for future use
        self.feature_columns = X.columns.tolist()
        
        # Scale the data
        X_scaled = self.scaler.fit_transform(X)
        
        # Apply PCA if requested
        if use_pca:
            self.pca = PCA(n_components=n_components)
            X_scaled = self.pca.fit_transform(X_scaled)
        
        # Initialize and fit the model
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1  # Use all available cores
        )
        self.model.fit(X_scaled)
    
    def predict(self, X):
        """
        Predict anomaly scores for new data
        
        Args:
            X (pd.DataFrame): Feature dataframe
            
        Returns:
            np.array: Anomaly scores (-1 for anomalies, 1 for normal)
        """
        # Prepare data
        X_prepared = self._prepare_data(X)
        
        # Predict anomalies
        return self.model.predict(X_prepared)
    
    def decision_function(self, X):
        """
        Get anomaly scores (lower = more anomalous)
        
        Args:
            X (pd.DataFrame): Feature dataframe
            
        Returns:
            np.array: Anomaly scores (0-1 range, higher = more anomalous)
        """
        # Prepare data
        X_prepared = self._prepare_data(X)
        
        # Get decision scores
        scores = self.model.decision_function(X_prepared)
        
        # Convert to 0-1 range where higher is more anomalous
        min_score = scores.min()
        max_score = scores.max()
        
        if max_score > min_score:
            normalized_scores = 1 - ((scores - min_score) / (max_score - min_score))
        else:
            normalized_scores = np.zeros_like(scores)
        
        return normalized_scores
    
    def _prepare_data(self, X):
        """
        Prepare data for prediction
        
        Args:
            X (pd.DataFrame): Feature dataframe
            
        Returns:
            np.array: Prepared data
        """
        # Ensure X has the same columns as training data
        if isinstance(X, pd.DataFrame) and self.feature_columns:
            # Add any missing columns with zeros
            for col in self.feature_columns:
                if col not in X.columns:
                    X[col] = 0
            
            # Select only the columns used in training
            X = X[self.feature_columns]
        
        # Scale the data
        X_scaled = self.scaler.transform(X)
        
        # Apply PCA if it was used in training
        if self.pca is not None:
            X_scaled = self.pca.transform(X_scaled)
        
        return X_scaled
    
    def save(self, filepath):
        """Save the model to disk"""
        with open(filepath, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler,
                'pca': self.pca,
                'contamination': self.contamination,
                'feature_columns': self.feature_columns
            }, f)
    
    @classmethod
    def load(cls, filepath):
        """Load a saved model"""
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
        
        instance = cls(contamination=data['contamination'])
        instance.model = data['model']
        instance.scaler = data['scaler']
        instance.pca = data['pca']
        instance.feature_columns = data['feature_columns']
        
        return instance

# models/supervised.py

from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np
import pickle

class RandomForestModel:
    """
    Random Forest classifier for supervised attack detection
    """
    
    def __init__(self, n_estimators=100, max_depth=None):
        """
        Initialize the classifier
        
        Args:
            n_estimators (int): Number of trees in the forest
            max_depth (int): Maximum depth of trees
        """
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=42,
            n_jobs=-1  # Use all CPU cores
        )
        self.scaler = StandardScaler()
        self.feature_columns = None
        
    def fit(self, X, y):
        """
        Fit the classifier
        
        Args:
            X (pd.DataFrame): Features
            y (pd.Series): Labels (0=normal, 1=attack)
        """
        # Store feature columns
        self.feature_columns = X.columns.tolist()
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Fit the model
        self.model.fit(X_scaled, y)
        
        # Get feature importances for later use
        self.feature_importances = pd.Series(
            self.model.feature_importances_,
            index=self.feature_columns
        ).sort_values(ascending=False)
        
    def predict(self, X):
        """
        Predict classes
        
        Args:
            X (pd.DataFrame): Features
            
        Returns:
            np.array: Predicted classes (0=normal, 1=attack)
        """
        X_prepared = self._prepare_data(X)
        return self.model.predict(X_prepared)
    
    def predict_proba(self, X):
        """
        Predict class probabilities
        
        Args:
            X (pd.DataFrame): Features
            
        Returns:
            np.array: Class probabilities ([:,1] gives attack probability)
        """
        X_prepared = self._prepare_data(X)
        return self.model.predict_proba(X_prepared)
    
    def _prepare_data(self, X):
        """
        Prepare data for prediction
        
        Args:
            X (pd.DataFrame): Features
            
        Returns:
            np.array: Prepared features
        """
        # Handle missing columns
        if isinstance(X, pd.DataFrame) and self.feature_columns:
            # Add missing columns
            for col in self.feature_columns:
                if col not in X.columns:
                    X[col] = 0
            
            # Select only training columns
            X = X[self.feature_columns]
        
        # Scale data
        return self.scaler.transform(X)
    
    def get_top_features(self, n=10):
        """
        Get the top N most important features
        
        Args:
            n (int): Number of features to return
            
        Returns:
            pd.Series: Top features and their importance
        """
        if hasattr(self, 'feature_importances'):
            return self.feature_importances.head(n)
        return None
    
    def save(self, filepath):
        """Save the model to disk"""
        with open(filepath, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler,
                'feature_columns': self.feature_columns,
                'feature_importances': self.feature_importances if hasattr(self, 'feature_importances') else None
            }, f)
    
    @classmethod
    def load(cls, filepath):
        """Load a saved model"""
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
        
        instance = cls()
        instance.model = data['model']
        instance.scaler = data['scaler']
        instance.feature_columns = data['feature_columns']
        if data['feature_importances'] is not None:
            instance.feature_importances = data['feature_importances']
        
        return instance

# models/ensemble.py

class EnsembleDetector:
    """
    Ensemble of multiple detection models
    """
    
    def __init__(self, models=None, weights=None):
        """
        Initialize the ensemble
        
        Args:
            models (list): List of model objects with predict and decision_function methods
            weights (list): List of weights for each model
        """
        self.models = models if models else []
        self.weights = weights if weights else [1.0] * len(self.models)
        
    def add_model(self, model, weight=1.0):
        """
        Add a model to the ensemble
        
        Args:
            model: Model with predict and decision_function methods
            weight (float): Weight for this model
        """
        self.models.append(model)
        self.weights.append(weight)
        
    def predict(self, X):
        """
        Predict using ensemble
        
        Args:
            X: Feature data
            
        Returns:
            np.array: Predictions (-1=anomaly, 1=normal)
        """
        if not self.models:
            raise ValueError("No models in the ensemble")
            
        # Get predictions from each model
        all_predictions = []
        for model in self.models:
            all_predictions.append(model.predict(X))
            
        # Stack and weight predictions
        stacked = np.stack(all_predictions)
        weighted_avg = np.average(stacked, axis=0, weights=self.weights)
        
        # Convert to binary predictions
        return np.where(weighted_avg < 0, -1, 1)
    
    def decision_function(self, X):
        """
        Get anomaly scores from ensemble
        
        Args:
            X: Feature data
            
        Returns:
            np.array: Anomaly scores (0-1 range, higher = more anomalous)
        """
        if not self.models:
            raise ValueError("No models in the ensemble")
            
        # Get scores from each model
        all_scores = []
        for model in self.models:
            all_scores.append(model.decision_function(X))
            
        # Stack and weight scores
        stacked = np.stack(all_scores)
        return np.average(stacked, axis=0, weights=self.weights)
    
    def save(self, filepath):
        """
        Save the ensemble configuration (not the models)
        
        Args:
            filepath (str): Path to save the configuration
        """
        # Only save the weights, models need to be saved separately
        with open(filepath, 'wb') as f:
            pickle.dump({
                'weights': self.weights
            }, f)
    
    @classmethod
    def load(cls, filepath, models):
        """
        Load an ensemble configuration
        
        Args:
            filepath (str): Path to the saved configuration
            models (list): List of loaded model objects
            
        Returns:
            EnsembleDetector: Loaded ensemble
        """
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
        
        return cls(models=models, weights=data['weights'])
