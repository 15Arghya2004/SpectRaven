# spectraven/plugins.py
import os
import importlib.util
import inspect
from .checks import BaseCheck

class PluginManager:
    def __init__(self, plugin_dir=None):
        self.plugin_dir = plugin_dir or os.path.join(os.path.dirname(__file__), 'plugins')
        self.plugins = []
        self.load_plugins()
    
    def load_plugins(self):
        """Load all plugins from the plugins directory"""
        if not os.path.exists(self.plugin_dir):
            os.makedirs(self.plugin_dir)
            return
        
        for filename in os.listdir(self.plugin_dir):
            if filename.endswith('.py') and not filename.startswith('_'):
                self._load_plugin(filename)
    
    def _load_plugin(self, filename):
        """Load a single plugin file"""
        try:
            plugin_path = os.path.join(self.plugin_dir, filename)
            spec = importlib.util.spec_from_file_location(filename[:-3], plugin_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find all classes that inherit from BaseCheck
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, BaseCheck) and 
                    obj != BaseCheck):
                    self.plugins.append(obj())
                    
        except Exception as e:
            print(f"Failed to load plugin {filename}: {e}")
    
    def get_plugins(self):
        """Get all loaded plugins"""
        return self.plugins