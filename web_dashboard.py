#!/usr/bin/env python3
"""
Web dashboard for Suricata JSON analysis
"""
import os
import json
import logging
import threading
import time
import datetime
from typing import Dict, List, Any, Optional
import pandas as pd
import numpy as np
from flask import Flask, render_template, request, jsonify, redirect, url_for
import plotly
import plotly.graph_objs as go
from plotly.subplots import make_subplots
import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import dash_bootstrap_components as dbc
from flask_socketio import SocketIO

# Local imports
from ml_module import MLModel
from realtime_monitor import RealTimeMonitor, AlertManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('web_dashboard')

# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'suricata-analyzer-secret-key'
socketio = SocketIO(app)

# Create Dash app
dash_app = dash.Dash(__name__, server=app, url_base_pathname='/dashboard/', 
                   external_stylesheets=[dbc.themes.BOOTSTRAP])

# Configuration
config = {
    'model_dir': os.environ.get('MODEL_DIR', 'models'),
    'log_file': os.environ.get('LOG_FILE', '/var/log/suricata/eve.json'),
    'telegram_token': os.environ.get('TELEGRAM_TOKEN', None),
    'telegram_chat_id': os.environ.get('TELEGRAM_CHAT_ID', None),
    'data_dir': os.environ.get('DATA_DIR', 'data'),
}

# Initialize components
ml_model = MLModel(config['model_dir'])
alert_manager = AlertManager(config['telegram_token'], config['telegram_chat_id'])
monitor = RealTimeMonitor(
    config['log_file'],
    config['model_dir'],
    config['telegram_token'],
    config['telegram_chat_id']
)

# Global state
analysis_results = {}
recent_alerts = []
traffic_stats = {
    'total_flows': 0,
    'total_alerts': 0,
    'alert_rate': 0,
    'total_bytes': 0,
    'bytes_per_second': 0,
    'anomaly_score': 0,
}
time_series_data = {
    'timestamps': [],
    'flow_counts': [],
    'alert_counts': [],
    'bytes_transferred': [],
}


def update_stats():
    """Update traffic statistics and time series data"""
    global traffic_stats, time_series_data, recent_alerts
    
    while True:
        try:
            # Get recent alerts
            recent_alerts = alert_manager.get_recent_alerts()
            alert_count = len(recent_alerts)
            
            # Update stats
            traffic_stats['total_alerts'] = alert_count
            
            if traffic_stats['total_flows'] > 0:
                traffic_stats['alert_rate'] = alert_count / traffic_stats['total_flows']
            
            # Update time series
            now = datetime.datetime.now()
            time_series_data['timestamps'].append(now)
            time_series_data['alert_counts'].append(alert_count)
            
            # Keep only last 1000 data points
            max_points = 1000
            if len(time_series_data['timestamps']) > max_points:
                time_series_data['timestamps'] = time_series_data['timestamps'][-max_points:]
                time_series_data['flow_counts'] = time_series_data['flow_counts'][-max_points:]
                time_series_data['alert_counts'] = time_series_data['alert_counts'][-max_points:]
                time_series_data['bytes_transferred'] = time_series_data['bytes_transferred'][-max_points:]
            
            # Emit updates via Socket.IO
            socketio.emit('stats_update', traffic_stats)
            socketio.emit('alerts_update', recent_alerts[:100])  # Send only last 100 alerts
            
            # Sleep for a bit
            time.sleep(5)
            
        except Exception as e:
            logger.error(f"Error updating stats: {e}")
            time.sleep(5)


# Flask routes
@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html', 
                          stats=traffic_stats, 
                          alerts=recent_alerts[:10])


@app.route('/alerts')
def alerts():
    """Alerts page"""
    return render_template('alerts.html', alerts=recent_alerts)


@app.route('/flows')
def flows():
    """Flows page"""
    # Get top 100 most recent flows
    if 'results_df' in analysis_results and not analysis_results['results_df'].empty:
        flows = analysis_results['results_df'].head(100).to_dict('records')
    else:
        flows = []
        
    return render_template('flows.html', flows=flows)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """File upload and analysis page"""
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
            
        file = request.files['file']
        
        if file.filename == '':
            return redirect(request.url)
            
        if file:
            # Save file temporarily
            file_path = os.path.join(config['data_dir'], 'uploads', file.filename)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            file.save(file_path)
            
            # Analyze file
            results_df = monitor.analyze_static_file(file_path)
            
            # Store results
            analysis_results['results_df'] = results_df
            analysis_results['file_name'] = file.filename
            
            # Update stats
            if not results_df.empty:
                traffic_stats['total_flows'] += len(results_df)
                alert_count = results_df.get('has_alert', 0).sum() if 'has_alert' in results_df.columns else 0
                traffic_stats['total_alerts'] += alert_count
                traffic_stats['total_bytes'] += results_df.get('total_bytes', 0).sum() if 'total_bytes' in results_df.columns else 0
                
            return redirect(url_for('analysis'))
            
    return render_template('upload.html')


@app.route('/analysis')
def analysis():
    """Analysis results page"""
    if 'results_df' not in analysis_results or analysis_results['results_df'].empty:
        return redirect(url_for('upload'))
        
    # Generate plots
    plots = generate_analysis_plots(analysis_results['results_df'])
    
    return render_template('analysis.html', 
                          file_name=analysis_results.get('file_name', ''),
                          plots=plots)


@app.route('/api/alerts')
def api_alerts():
    """API endpoint for alerts"""
    return jsonify(recent_alerts)


@app.route('/api/stats')
def api_stats():
    """API endpoint for stats"""
    return jsonify(traffic_stats)


@app.route('/api/timeseries')
def api_timeseries():
    """API endpoint for time series data"""
    # Convert timestamps to strings
    formatted_timestamps = [ts.isoformat() for ts in time_series_data['timestamps']]
    
    data = {
        'timestamps': formatted_timestamps,
        'flow_counts': time_series_data['flow_counts'],
        'alert_counts': time_series_data['alert_counts'],
        'bytes_transferred': time_series_data['bytes_transferred'],
    }
    
    return jsonify(data)


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for analyzing a file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
        
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        
    if file:
        # Save file temporarily
        file_path = os.path.join(config['data_dir'], 'uploads', file.filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        file.save(file_path)
        
        # Analyze file
        results_df = monitor.analyze_static_file(file_path)
        
        # Convert results to JSON
        if not results_df.empty:
            # Basic stats
            flow_count = len(results_df)
            alert_count = results_df.get('has_alert', 0).sum() if 'has_alert' in results_df.columns else 0
            anomaly_count = results_df.get('anomaly_prediction', 0).sum() if 'anomaly_prediction' in results_df.columns else 0
            
            return jsonify({
                'success': True,
                'file_name': file.filename,
                'flow_count': flow_count,
                'alert_count': alert_count,
                'anomaly_count': anomaly_count,
                'results': results_df.head(100).to_dict('records')  # Send only top 100 results
            })
        else:
            return jsonify({
                'success': False,
                'error': 'No results extracted from file'
            }), 400
            
    return jsonify({'error': 'File processing failed'}), 500


# Helper functions
def generate_analysis_plots(df):
    """
    Generate analysis plots from results DataFrame
    
    Args:
        df: Results DataFrame
        
    Returns:
        Dictionary of plot HTML
    """
    plots = {}
    
    try:
        # 1. Protocol distribution
        if 'protocol' in df.columns:
            proto_counts = df['protocol'].value_counts()
            
            fig = go.Figure(data=[
                go.Pie(
                    labels=proto_counts.index,
                    values=proto_counts.values,
                    hole=0.4,
                    textinfo='label+percent',
                    marker=dict(colors=['#636EFA', '#EF553B', '#00CC96', '#AB63FA', '#FFA15A'])
                )
            ])
            
            fig.update_layout(
                title='Protocol Distribution',
                height=400,
                margin=dict(l=50, r=50, t=80, b=50)
            )
            
            plots['protocol_dist'] = plotly.io.to_html(fig, full_html=False)
            
        # 2. Bytes transferred over time
        if 'timestamp' in df.columns and 'total_bytes' in df.columns:
            # Convert timestamp to datetime if needed
            if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                
            # Group by hour
            df['hour'] = df['timestamp'].dt.floor('H')
            bytes_by_hour = df.groupby('hour')['total_bytes'].sum().reset_index()
            
            fig = go.Figure(data=[
                go.Scatter(
                    x=bytes_by_hour['hour'],
                    y=bytes_by_hour['total_bytes'],
                    mode='lines+markers',
                    line=dict(width=2, color='#00CC96'),
                    marker=dict(size=8, color='#00CC96')
                )
            ])
            
            fig.update_layout(
                title='Data Transfer Volume Over Time',
                xaxis_title='Time',
                yaxis_title='Bytes Transferred',
                height=400,
                margin=dict(l=50, r=50, t=80, b=50)
            )
            
            plots['bytes_over_time'] = plotly.io.to_html(fig, full_html=False)
            
        # 3. Alert distribution by type (if available)
        if 'alert_category' in df.columns:
            alert_counts = df['alert_category'].value_counts().head(10)  # Top 10 categories
            
            fig = go.Figure(data=[
                go.Bar(
                    x=alert_counts.index,
                    y=alert_counts.values,
                    marker_color='#EF553B'
                )
            ])
            
            fig.update_layout(
                title='Top Alert Categories',
                xaxis_title='Category',
                yaxis_title='Count',
                height=400,
                margin=dict(l=50, r=50, t=80, b=50)
            )
            
            plots['alert_categories'] = plotly.io.to_html(fig, full_html=False)
            
        # 4. Anomaly score distribution (if available)
        if 'anomaly_score' in df.columns:
            fig = go.Figure(data=[
                go.Histogram(
                    x=df['anomaly_score'],
                    nbinsx=20,
                    marker_color='#AB63FA'
                )
            ])
            
            fig.update_layout(
                title='Anomaly Score Distribution',
                xaxis_title='Anomaly Score',
                yaxis_title='Count',
                height=400,
                margin=dict(l=50, r=50, t=80, b=50)
            )
            
            plots['anomaly_dist'] = plotly.io.to_html(fig, full_html=False)
            
        # 5. Port distribution (top 10)
        if 'dst_port' in df.columns:
            port_counts = df['dst_port'].value_counts().head(10)
            
            fig = go.Figure(data=[
                go.Bar(
                    x=port_counts.index.astype(str),
                    y=port_counts.values,
                    marker_color='#FFA15A'
                )
            ])
            
            fig.update_layout(
                title='Top Destination Ports',
                xaxis_title='Port',
                yaxis_title='Count',
                height=400,
                margin=dict(l=50, r=50, t=80, b=50)
            )
            
            plots['port_dist'] = plotly.io.to_html(fig, full_html=False)
            
    except Exception as e:
        logger.error(f"Error generating plots: {e}")
        
    return plots


# Define Dash layout
dash_app.layout = html.Div([
    dbc.NavbarSimple(
        children=[
            dbc.NavItem(dbc.NavLink("Dashboard", href="/dashboard")),
            dbc.NavItem(dbc.NavLink("Alerts", href="/alerts")),
            dbc.NavItem(dbc.NavLink("Upload", href="/upload")),
        ],
        brand="Suricata Analyzer",
        brand_href="/",
        color="primary",
        dark=True,
    ),
    
    dbc.Container([
        dbc.Row([
            dbc.Col([
                html.H2("Real-time Network Traffic Analysis", className="mt-4"),
                html.Hr(),
            ]),
        ]),
        
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Traffic Statistics"),
                    dbc.CardBody([
                        dbc.Row([
                            dbc.Col([
                                html.H4(id="total-flows", children="0"),
                                html.P("Total Flows")
                            ]),
                            dbc.Col([
                                html.H4(id="total-alerts", children="0"),
                                html.P("Total Alerts")
                            ]),
                            dbc.Col([
                                html.H4(id="alert-rate", children="0%"),
                                html.P("Alert Rate")
                            ]),
                        ]),
                    ]),
                ]),
            ], width=12),
        ], className="mt-4"),
        
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Traffic Over Time"),
                    dbc.CardBody([
                        dcc.Graph(id="traffic-graph"),
                        dcc.Interval(
                            id='interval-component',
                            interval=5*1000,  # in milliseconds
                            n_intervals=0
                        )
                    ]),
                ]),
            ], width=12),
        ], className="mt-4"),
        
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Recent Alerts"),
                    dbc.CardBody([
                        html.Div(id="recent-alerts-table")
                    ]),
                ]),
            ], width=12),
        ], className="mt-4"),
    ]),
])


# Dash callbacks
@dash_app.callback(
    [Output("total-flows", "children"),
     Output("total-alerts", "children"),
     Output("alert-rate", "children")],
    [Input("interval-component", "n_intervals")]
)
def update_stats_cards(n):
    """Update stats cards"""
    return (
        f"{traffic_stats['total_flows']:,}",
        f"{traffic_stats['total_alerts']:,}",
        f"{traffic_stats['alert_rate']:.2%}"
    )


@dash_app.callback(
    Output("traffic-graph", "figure"),
    [Input("interval-component", "n_intervals")]
)
def update_traffic_graph(n):
    """Update traffic graph"""
    # Convert timestamps to readable format
    timestamps = [ts.strftime('%H:%M:%S') for ts in time_series_data['timestamps']]
    
    # Create subplot
    fig = make_subplots(specs=[[{"secondary_y": True}]])
    
    # Add flow counts
    fig.add_trace(
        go.Scatter(
            x=timestamps,
            y=time_series_data['flow_counts'],
            name="Flows",
            mode="lines",
            line=dict(color="#636EFA", width=2)
        ),
        secondary_y=False,
    )
    
    # Add alert counts
    fig.add_trace(
        go.Scatter(
            x=timestamps,
            y=time_series_data['alert_counts'],
            name="Alerts",
            mode="lines",
            line=dict(color="#EF553B", width=2)
        ),
        secondary_y=True,
    )
    
    # Update layout
    fig.update_layout(
        title="Network Traffic and Alerts Over Time",
        xaxis_title="Time",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        margin=dict(l=50, r=50, t=80, b=50),
        height=400
    )
    
    # Update y-axis labels
    fig.update_yaxes(title_text="Flow Count", secondary_y=False)
    fig.update_yaxes(title_text="Alert Count", secondary_y=True)
    
    return fig


@dash_app.callback(
    Output("recent-alerts-table", "children"),
    [Input("interval-component", "n_intervals")]
)
def update_alerts_table(n):
    """Update alerts table"""
    if not recent_alerts:
        return html.P("No alerts detected yet.")
        
    # Get last 10 alerts
    alerts = recent_alerts[-10:][::-1]
    
    # Create table
    table = dbc.Table([
        html.Thead([
            html.Tr([
                html.Th("Time"),
                html.Th("Type"),
                html.Th("Source"),
                html.Th("Destination"),
                html.Th("Severity"),
            ])
        ]),
        html.Tbody([
            html.Tr([
                html.Td(alert.get('timestamp', '').split('T')[1].split('.')[0]),
                html.Td(alert.get('type', 'Unknown')),
                html.Td(f"{alert.get('src_ip', '')}:{alert.get('src_port', '')}"),
                html.Td(f"{alert.get('dst_ip', '')}:{alert.get('dst_port', '')}"),
                html.Td(alert.get('severity', ''), style={
                    'color': 'red' if alert.get('severity') == 'High' else
                             'orange' if alert.get('severity') == 'Medium' else
                             'blue'
                }),
            ]) for alert in alerts
        ])
    ], bordered=True, hover=True, responsive=True, striped=True)
    
    return table


# HTML templates
# These would normally be in separate files, but for simplicity, we'll define them here
# You would place these in a templates directory in a real application

# Main template (index.html)
main_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Suricata Analyzer</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css">
    <style>
        body { padding-top: 20px; }
        .card { margin-bottom: 20px; }
        .alert-high { color: #721c24; background-color: #f8d7da; }
        .alert-medium { color: #856404; background-color: #fff3cd; }
        .alert-low { color: #0c5460; background-color: #d1ecf1; }
    </style>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
</head>
<body>
    <div class="container">
        <nav class="navbar navbar-expand-lg navbar-dark bg-primary mb-4">
            <div class="container-fluid">
                <a class="navbar-brand" href="/">Suricata Analyzer</a>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="collapse navbar-collapse" id="navbarNav">
                    <ul class="navbar-nav">
                        <li class="nav-item">
                            <a class="nav-link active" href="/">Dashboard</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/alerts">Alerts</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/flows">Flows</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/upload">Upload</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/dashboard">Advanced Dashboard</a>
                        </li>
                    </ul>
                </div>
            </div>
        </nav>

        <h1>Network Traffic Analysis</h1>
        <p class="lead">Real-time monitoring and analysis of Suricata logs using machine learning</p>

        <div class="row mt-4">
            <div class="col-md-4">
                <div class="card text-white bg-primary">
                    <div class="card-body">
                        <h5 class="card-title">Total Flows</h5>
                        <h2 id="total-flows">{{ stats.total_flows }}</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card text-white bg-danger">
                    <div class="card-body">
                        <h5 class="card-title">Alerts</h5>
                        <h2 id="total-alerts">{{ stats.total_alerts }}</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card text-white bg-success">
                    <div class="card-body">
                        <h5 class="card-title">Data Transferred</h5>
                        <h2 id="total-bytes">{{ stats.total_bytes|filesizeformat }}</h2>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mt-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        <h5>Traffic Over Time</h5>
                    </div>
                    <div class="card-body">
                        <div id="traffic-chart" style="height: 300px;"></div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mt-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        <h5>Recent Alerts</h5>
                    </div>
                    <div class="card-body">
                        <div id="alerts-table">
                            <table class="table table-striped table-hover">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Type</th>
                                        <th>Source</th>
                                        <th>Destination</th>
                                        <th>Severity</th>
                                        <th>Description</th>
                                    </tr>
                                </thead>
                                <tbody id="alerts-tbody">
                                    {% for alert in alerts %}
                                    <tr{% if alert.severity == "High" %} class="alert-high"{% elif alert.severity == "Medium" %} class="alert-medium"{% elif alert.severity == "Low" %} class="alert-low"{% endif %}>
                                        <td>{{ alert.timestamp }}</td>
                                        <td>{{ alert.type }}</td>
                                        <td>{{ alert.src_ip }}:{{ alert.src_port }}</td>
                                        <td>{{ alert.dst_ip }}:{{ alert.dst_port }}</td>
                                        <td>{{ alert.severity }}</td>
                                        <td>{{ alert.description }}</td>
                                    </tr>
                                    {% else %}
                                    <tr>
                                        <td colspan="6" class="text-center">No alerts detected yet</td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Connect to Socket.IO
        const socket = io();
        
        // Update stats
        socket.on('stats_update', function(stats) {
            document.getElementById('total-flows').innerText = stats.total_flows.toLocaleString();
            document.getElementById('total-alerts').innerText = stats.total_alerts.toLocaleString();
            document.getElementById('total-bytes').innerText = formatBytes(stats.total_bytes);
        });
        
        // Update alerts
        socket.on('alerts_update', function(alerts) {
            const tbody = document.getElementById('alerts-tbody');
            if (!tbody) return;
            
            let html = '';
            
            if (alerts.length === 0) {
                html = '<tr><td colspan="6" class="text-center">No alerts detected yet</td></tr>';
            } else {
                for (const alert of alerts.slice(0, 10)) {
                    const timestamp = alert.timestamp ? alert.timestamp.split('T')[1].split('.')[0] : '';
                    const severity = alert.severity || '';
                    let alertClass = '';
                    
                    if (severity === 'High') alertClass = 'alert-high';
                    else if (severity === 'Medium') alertClass = 'alert-medium';
                    else if (severity === 'Low') alertClass = 'alert-low';
                    
                    html += `
                        <tr class="${alertClass}">
                            <td>${timestamp}</td>
                            <td>${alert.type || ''}</td>
                            <td>${alert.src_ip || ''}:${alert.src_port || ''}</td>
                            <td>${alert.dst_ip || ''}:${alert.dst_port || ''}</td>
                            <td>${severity}</td>
                            <td>${alert.description || ''}</td>
                        </tr>
                    `;
                }
            }
            
            tbody.innerHTML = html;
        });
        
        // Helper function to format bytes
        function formatBytes(bytes, decimals = 2) {
            if (bytes === 0) return '0 Bytes';
            
            const k = 1024;
            const dm = decimals < 0 ? 0 : decimals;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
            
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            
            return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
        }
        
        // Create traffic chart
        async function createTrafficChart() {
            try {
                const response = await fetch('/api/timeseries');
                const data = await response.json();
                
                const timestamps = data.timestamps;
                const flowCounts = data.flow_counts;
                const alertCounts = data.alert_counts;
                
                const layout = {
                    margin: { t: 0, r: 0, l: 50, b: 50 },
                    xaxis: { title: 'Time' },
                    yaxis: { title: 'Count' },
                    showlegend: true
                };
                
                const plotData = [
                    {
                        x: timestamps,
                        y: flowCounts,
                        type: 'scatter',
                        mode: 'lines',
                        name: 'Flows',
                        line: { color: '#4285F4' }
                    },
                    {
                        x: timestamps,
                        y: alertCounts,
                        type: 'scatter',
                        mode: 'lines',
                        name: 'Alerts',
                        line: { color: '#DB4437' }
                    }
                ];
                
                Plotly.newPlot('traffic-chart', plotData, layout);
                
            } catch (error) {
                console.error('Error creating traffic chart:', error);
            }
        }
        
        // Initialize charts when page loads
        document.addEventListener('DOMContentLoaded', function() {
            createTrafficChart();
            
            // Update chart every 10 seconds
            setInterval(createTrafficChart, 10000);
        });
    </script>
</body>
</html>
"""

# Create directory structure for templates and static files
def create_directories():
    """Create necessary directories"""
    directories = [
        'templates',
        'static/css',
        'static/js',
        config['data_dir'],
        os.path.join(config['data_dir'], 'uploads'),
        config['model_dir'],
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        
    # Create templates
    with open('templates/index.html', 'w') as f:
        f.write(main_template)
        
    logger.info("Created directory structure and templates")


# Main function
def main():
    """Main function"""
    create_directories()
    
    # Start alert manager
    alert_manager.start()
    
    # Start stats update thread
    stats_thread = threading.Thread(target=update_stats)
    stats_thread.daemon = True
    stats_thread.start()
    
    # Start monitor if real-time monitoring is enabled
    if os.path.exists(config['log_file']):
        monitor.start()
        logger.info(f"Started monitoring {config['log_file']}")
    else:
        logger.warning(f"Log file {config['log_file']} not found, real-time monitoring disabled")
        
    # Start web server
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    finally:
        # Stop components
        alert_manager.stop()
        monitor.stop()


if __name__ == "__main__":
    main()
