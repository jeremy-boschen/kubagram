"""
Preview server for KubeViz diagrams.
"""

import logging
import os
import threading
import webbrowser
from typing import Optional

from flask import Flask, render_template, request, Response

logger = logging.getLogger(__name__)

def start_preview_server(
    diagram_content: str, 
    format_type: str = "svg", 
    port: int = 5000, 
    open_browser: bool = True
):
    """
    Start a Flask server to preview the diagram.
    
    Args:
        diagram_content: Diagram content (SVG or Mermaid)
        format_type: Format type ("svg" or "mermaid")
        port: Port to run the server on
        open_browser: Whether to open a browser window
    """
    app = Flask(__name__)
    
    @app.route('/')
    def preview():
        return render_template(
            'preview.html',
            diagram_content=diagram_content,
            format_type=format_type
        )
    
    @app.route('/diagram')
    def diagram():
        if format_type == "svg":
            return Response(diagram_content, content_type='image/svg+xml')
        else:
            return Response(diagram_content, content_type='text/plain')
    
    # Open browser in a separate thread
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(f'http://localhost:{port}')).start()
    
    logger.info(f"Starting preview server at http://localhost:{port}")
    app.run(host='0.0.0.0', port=port, debug=False)
