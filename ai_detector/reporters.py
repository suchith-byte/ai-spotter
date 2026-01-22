"""Output formatters for detection results."""

import csv
import io
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict

from .config import get_config
from .detectors import DetectionResult


class BaseReporter:
    """Base class for reporters."""
    
    def generate(self, results: List[DetectionResult]) -> str:
        """Generate report from results."""
        raise NotImplementedError


class JSONReporter(BaseReporter):
    """JSON output formatter."""
    
    def generate(self, results: List[DetectionResult]) -> str:
        """Generate JSON report."""
        # Group results by service
        grouped = defaultdict(list)
        for result in results:
            grouped[result.service_name].append(result.to_dict())
        
        report = {
            'scan_timestamp': datetime.utcnow().isoformat(),
            'total_detections': len(results),
            'services_found': list(grouped.keys()),
            'detections_by_service': dict(grouped),
            'summary': {
                'by_type': self._count_by_type(results),
                'by_severity': self._count_by_severity(results),
            }
        }
        
        return json.dumps(report, indent=2)
    
    def _count_by_type(self, results: List[DetectionResult]) -> Dict[str, int]:
        """Count detections by type."""
        counts = defaultdict(int)
        for result in results:
            counts[result.detection_type] += 1
        return dict(counts)
    
    def _count_by_severity(self, results: List[DetectionResult]) -> Dict[str, int]:
        """Count detections by severity."""
        counts = defaultdict(int)
        for result in results:
            counts[result.severity] += 1
        return dict(counts)


class TextReporter(BaseReporter):
    """Human-readable text output formatter."""
    
    def __init__(self):
        self.config = get_config().output
    
    def generate(self, results: List[DetectionResult]) -> str:
        """Generate human-readable text report."""
        if not results:
            return "No AI services detected in the repository.\n"
        
        # Group by service
        grouped = defaultdict(list)
        for result in results:
            grouped[result.service_name].append(result)
        
        width = self.config.report_line_width
        lines = []
        lines.append("=" * width)
        lines.append("AI SERVICE DETECTION REPORT")
        lines.append("=" * width)
        lines.append(f"Scan Date: {datetime.now(timezone.utc).strftime(self.config.date_format)}")
        lines.append(f"Total Detections: {len(results)}")
        lines.append(f"Services Found: {len(grouped)}")
        lines.append("")
        
        # Summary by severity
        severity_counts = defaultdict(int)
        for result in results:
            severity_counts[result.severity] += 1
        
        lines.append("Summary by Severity:")
        for severity in ['critical', 'warning', 'info']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                lines.append(f"  {severity.upper()}: {count}")
        lines.append("")
        
        # Detailed findings by service
        for service_name in sorted(grouped.keys()):
            service_results = grouped[service_name]
            lines.append("-" * width)
            lines.append(f"Service: {service_name}")
            lines.append(f"Total Findings: {len(service_results)}")
            lines.append("-" * width)
            
            # Group by detection type
            by_type = defaultdict(list)
            for result in service_results:
                by_type[result.detection_type].append(result)
            
            for det_type in ['dependency', 'config', 'code', 'endpoint']:
                if det_type in by_type:
                    lines.append(f"\n{det_type.upper()} Detections:")
                    for result in by_type[det_type]:
                        # Use hyperlink if available
                        file_path_display = result.get_hyperlink() if result.repo_url else result.file_path
                        lines.append(f"  File: {file_path_display}")
                        if result.line_number:
                            lines.append(f"    Line {result.line_number}: {result.evidence[:100]}")
                        else:
                            lines.append(f"    {result.evidence[:100]}")
                        lines.append(f"    Severity: {result.severity}")
                        lines.append("")
        
        lines.append("=" * width)
        return "\n".join(lines)


class CSVReporter(BaseReporter):
    """CSV output formatter."""
    
    def __init__(self):
        self.config = get_config().output
    
    def generate(self, results: List[DetectionResult]) -> str:
        """Generate CSV report."""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Service Name',
            'Detection Type',
            'File Path',
            'Line Number',
            'Evidence',
            'Severity'
        ])
        
        # Write data
        max_evidence = self.config.max_evidence_length
        for result in results:
            # Use hyperlink if available, otherwise use file path
            file_path_display = result.get_hyperlink() if result.repo_url else result.file_path
            writer.writerow([
                result.service_name,
                result.detection_type,
                file_path_display,
                result.line_number or '',
                result.evidence[:max_evidence],
                result.severity
            ])
        
        return output.getvalue()


class ReporterManager:
    """Manages multiple reporters and output formats."""
    
    def __init__(self):
        self.reporters = {
            'json': JSONReporter(),
            'text': TextReporter(),
            'csv': CSVReporter(),
        }
    
    def _validate_output_path(self, output_file: str) -> Path:
        """Validate output file path to prevent path traversal attacks.
        
        Args:
            output_file: The output file path to validate.
            
        Returns:
            Validated Path object.
            
        Raises:
            ValueError: If path is invalid or potentially dangerous.
        """
        path = Path(output_file)
        
        # Resolve to absolute path and check for traversal
        try:
            resolved = path.resolve()
        except (OSError, RuntimeError) as e:
            raise ValueError(f"Invalid output path: {e}")
        
        # Block absolute paths that go to sensitive locations
        # Include /private/* for macOS where /etc -> /private/etc
        sensitive_prefixes = [
            '/etc', '/usr', '/bin', '/sbin', '/var', '/root', '/sys', '/proc',
            '/private/etc', '/private/var', '/System', '/Library',
        ]
        resolved_str = str(resolved)
        for prefix in sensitive_prefixes:
            if resolved_str.startswith(prefix):
                raise ValueError(f"Cannot write to system directory: {prefix}")
        
        # Ensure parent directory exists or can be created
        parent = resolved.parent
        if not parent.exists():
            raise ValueError(f"Parent directory does not exist: {parent}")
        
        return resolved
    
    def generate_report(
        self,
        results: List[DetectionResult],
        format: str = 'text',
        output_file: str = None
    ) -> str:
        """
        Generate report in specified format.
        
        Args:
            results: List of detection results
            format: Output format ('json', 'text', 'csv', or 'all')
            output_file: Optional file path to write output
        
        Returns:
            Generated report string(s)
        """
        if format == 'all':
            outputs = {}
            for fmt, reporter in self.reporters.items():
                outputs[fmt] = reporter.generate(results)
            
            if output_file:
                # Validate and write all formats to separate files
                base_path = self._validate_output_path(output_file)
                for fmt, content in outputs.items():
                    if fmt == 'json':
                        file_path = base_path.with_suffix('.json')
                    elif fmt == 'csv':
                        file_path = base_path.with_suffix('.csv')
                    else:
                        file_path = base_path.with_suffix('.txt')
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)
            
            return "\n\n".join([f"=== {fmt.upper()} ===\n{content}" for fmt, content in outputs.items()])
        
        else:
            if format not in self.reporters:
                raise ValueError(f"Unknown format: {format}. Choose from: {', '.join(self.reporters.keys())}, all")
            
            reporter = self.reporters[format]
            output = reporter.generate(results)
            
            if output_file:
                validated_path = self._validate_output_path(output_file)
                with open(validated_path, 'w', encoding='utf-8') as f:
                    f.write(output)
            
            return output

