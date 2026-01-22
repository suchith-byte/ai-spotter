"""AI Service Registry - Database of AI services and detection patterns.

This module loads AI service definitions from a YAML configuration file,
making it easy to add new services or modify detection patterns without
changing Python code.
"""

import re
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Pattern, Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class AIService:
    """Represents an AI service with its detection patterns."""
    name: str
    package_names: List[str] = field(default_factory=list)
    import_patterns: List[Pattern] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    config_key_patterns: List[str] = field(default_factory=list)
    model_patterns: List[Pattern] = field(default_factory=list)
    client_patterns: List[Pattern] = field(default_factory=list)


def _compile_patterns(patterns: List[str], case_insensitive: bool = True) -> List[Pattern]:
    """Compile a list of regex pattern strings into Pattern objects."""
    flags = re.IGNORECASE if case_insensitive else 0
    compiled = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern, flags))
        except re.error as e:
            logger.warning(f"Invalid regex pattern '{pattern}': {e}")
    return compiled


def _load_services_from_yaml(yaml_path: Path) -> List[AIService]:
    """Load AI service definitions from a YAML file."""
    with open(yaml_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    
    services = []
    for svc_data in data.get('services', []):
        service = AIService(
            name=svc_data['name'],
            package_names=svc_data.get('package_names', []),
            import_patterns=_compile_patterns(svc_data.get('import_patterns', [])),
            api_endpoints=svc_data.get('api_endpoints', []),
            config_key_patterns=svc_data.get('config_key_patterns', []),
            model_patterns=_compile_patterns(svc_data.get('model_patterns', [])),
            client_patterns=_compile_patterns(svc_data.get('client_patterns', [])),
        )
        services.append(service)
    
    return services


class AIServiceRegistry:
    """Registry of all AI services to detect."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize the registry.
        
        Args:
            config_path: Path to YAML config file. If not provided,
                        uses services.yaml in the same directory.
        """
        if config_path is None:
            config_path = Path(__file__).parent / 'services.yaml'
        
        self.services = _load_services_from_yaml(config_path)
    
    def get_all_services(self) -> List[AIService]:
        """Get all registered AI services."""
        return self.services
    
    def get_service_by_name(self, name: str) -> AIService:
        """Get a specific service by name.
        
        Args:
            name: Service name (case-insensitive).
        
        Returns:
            The matching AIService.
        
        Raises:
            ValueError: If service not found.
        """
        for service in self.services:
            if service.name.lower() == name.lower():
                return service
        raise ValueError(f"Service '{name}' not found in registry")
    
    def get_all_package_names(self) -> List[str]:
        """Get all package names from all services."""
        packages = []
        for service in self.services:
            packages.extend(service.package_names)
        return packages
    
    def add_service(self, service: AIService) -> None:
        """Add a new service to the registry.
        
        Args:
            service: The AIService to add.
        """
        self.services.append(service)
    
    def __len__(self) -> int:
        """Return the number of registered services."""
        return len(self.services)
    
    def __iter__(self):
        """Iterate over registered services."""
        return iter(self.services)
