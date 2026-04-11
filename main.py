import argparse
import re
import sys
import logging
import pathlib
from typing import List, Pattern, Optional

class LogVigilanteError(Exception):
    """Base exception for LogVigilante tool."""
    pass

class ConfigurationError(LogVigilanteError):
    """Raised when CLI arguments or regex patterns are invalid."""
    pass

class ProcessingError(LogVigilanteError):
    """Raised when file I/O or stream processing fails."""

class LogProcessor:
    """
    Core logic for scanning and sanitizing log files.
    
    Attributes:
        input_path (pathlib.Path): Source log file.
        output_path (pathlib.Path): Destination for sanitized output.
        patterns (List[Pattern]): Compiled regex objects for masking.
        mask_char (str): Character used to replace sensitive matches.
    """

    def __init__(self, input_path: str, output_path: str, patterns: List[str], mask_char: str = "*"):
        self.input_path = pathlib.Path(input_path)
        self.output_path = pathlib.Path(output_path)
        self.mask_char = mask_char
        self.patterns = self._compile_patterns(patterns)
        self._validate_paths()

    def _compile_patterns(self, patterns: List[str]) -> List[Pattern]:
        """Compiles regex strings into objects with error handling for malformed syntax."""
        compiled = []
        for p in patterns:
            try:
                compiled.append(re.compile(p))
            except re.error as e:
                raise ConfigurationError(f"Invalid regex pattern '{p}': {e}")
        return compiled

    def _validate_paths(self):
        """Ensures filesystem integrity before processing."""
        if not self.input_path.exists():
            raise ConfigurationError(f"Input file not found: {self.input_path}")
        if not self.input_path.is_file():
            raise ConfigurationError(f"Input path is not a file: {self.input_path}")
        if self.input_path == self.output_path:
            raise ConfigurationError("Input and output paths must be different to prevent data loss.")

    def process(self):
        """
        Streams the file line-by-line to minimize memory footprint and applies masking.
        
        Raises:
            ProcessingError: If disk is full or permissions are lost during stream.
        """
        try:
            with self.input_path.open('r', encoding='utf-8') as fin, \
                 self.output_path.open('w', encoding='utf-8') as fout:
                for line_no, line in enumerate(fin, 1):
                    sanitized_line = line
                    for pattern in self.patterns:
                        sanitized_line = pattern.sub(lambda m: self.mask_char * len(m.group(0)), sanitized_line)
                    fout.write(sanitized_line)
        except (OSError, IOError) as e:
            raise ProcessingError(f"Failed during file streaming at line {line_no}: {e}")

def main():
    parser = argparse.ArgumentParser(description="LogVigilante: Robust Log Sanitizer")
    parser.add_argument("--input", "-i", required=True, help="Path to raw log file")
    parser.add_argument("--output", "-o", required=True, help="Path to write sanitized log")
    parser.add_argument("--patterns", "-p", nargs='+', default=[r"\b\d{4}-\d{4}-\d{4}-\d{4}\b"], help="Regex patterns to mask")
    parser.add_argument("--mask-char", default="*", help="Character to use for masking")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')

    try:
        processor = LogProcessor(args.input, args.output, args.patterns, args.mask_char)
        logging.info(f"Starting sanitization: {args.input} -> {args.output}")
        processor.process()
        logging.info("Sanitization completed successfully.")
    except LogVigilanteError as e:
        logging.error(f"Application Error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"Unexpected Runtime Failure: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()