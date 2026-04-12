import argparse
import re
import sys
import logging
import pathlib
from typing import List, Pattern, Optional, Dict

class LogVigilanteError(Exception):
    """Base exception for LogVigilante tool."""
    pass

class ConfigurationError(LogVigilanteError):
    """Raised when CLI arguments or regex patterns are invalid."""
    pass

class ProcessingError(LogVigilanteError):
    """Raised when file I/O or stream processing fails."""
    pass

class LogProcessor:
    """
    Core logic for scanning and sanitizing log files using a Fail-Fast philosophy.

    This processor ensures that all system-level requirements (permissions, path existence,
    regex validity) are met during initialization before any file handles are opened.
    
    :param input_path: String path to the source log file.
    :param output_path: String path to the destination sanitized file.
    :param patterns: List of raw regex strings to identify sensitive data.
    :param mask_char: Character used to replace sensitive matches. Defaults to '*'.
    """

    def __init__(self, input_path: str, output_path: str, patterns: List[str], mask_char: str = "*"):
        self.input_path = pathlib.Path(input_path)
        self.output_path = pathlib.Path(output_path)
        self.mask_char = mask_char
        self.patterns = self._compile_patterns(patterns)
        self.redaction_count = 0
        self._validate_paths()

    def _compile_patterns(self, patterns: List[str]) -> List[Pattern]:
        """
        Compiles regex strings into objects.

        :raises ConfigurationError: If a pattern is syntactically invalid.
        """
        if not patterns:
            raise ConfigurationError("No patterns provided for sanitization.")
        
        compiled = []
        for p in patterns:
            try:
                compiled.append(re.compile(p))
            except re.error as e:
                raise ConfigurationError(f"Invalid regex pattern '{p}': {e}")
        return compiled

    def _validate_paths(self):
        """
        Ensures filesystem integrity before processing.

        Checks include existence of input, writability of output parent,
        and path collisions.

        :raises ConfigurationError: If path validation fails.
        """
        if not self.input_path.exists():
            raise ConfigurationError(f"Input file not found: {self.input_path}")
        if not self.input_path.is_file():
            raise ConfigurationError(f"Input path is not a file: {self.input_path}")
        if self.input_path == self.output_path:
            raise ConfigurationError("Input and output paths must be different to prevent data loss.")
        
        # Check if output directory exists and is writable
        output_dir = self.output_path.parent
        if not output_dir.exists():
            raise ConfigurationError(f"Output directory does not exist: {output_dir}")
        if not (output_dir.is_dir() and (sys.platform == 'win32' or output_dir.stat().st_mode & 0o200)):
            raise ConfigurationError(f"Output directory is not writable: {output_dir}")

    def _mask_match(self, match: re.Match) -> str:
        """Internal helper to count matches and return mask string."""
        self.redaction_count += 1
        return self.mask_char * len(match.group(0))

    def process(self) -> int:
        """
        Streams the file line-by-line to minimize memory footprint and applies masking.

        Uses context managers to ensure safe resource disposal even on failure.
        
        :return: Total number of redactions performed.
        :raises ProcessingError: If disk is full, permissions are lost, or encoding fails.
        """
        line_no = 0
        try:
            with self.input_path.open('r', encoding='utf-8', errors='replace') as fin, \
                 self.output_path.open('w', encoding='utf-8') as fout:
                for line in fin:
                    line_no += 1
                    sanitized_line = line
                    for pattern in self.patterns:
                        sanitized_line = pattern.sub(self._mask_match, sanitized_line)
                    fout.write(sanitized_line)
            return self.redaction_count
        except (OSError, IOError) as e:
            raise ProcessingError(f"Failed during file streaming at line {line_no}: {e}")
        except Exception as e:
            raise ProcessingError(f"Unexpected error at line {line_no}: {e}")

def main():
    parser = argparse.ArgumentParser(description="LogVigilante: Robust Log Sanitizer")
    parser.add_argument("--input", "-i", required=True, help="Path to raw log file")
    parser.add_argument("--output", "-o", required=True, help="Path to write sanitized log")
    parser.add_argument("--patterns", "-p", nargs='+', default=[r"\b\d{4}-\d{4}-\d{4}-\d{4}\b"], help="Regex patterns to mask")
    parser.add_argument("--mask-char", default="*", help="Character to use for masking")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s [%(levelname)s] %(message)s')

    try:
        processor = LogProcessor(args.input, args.output, args.patterns, args.mask_char)
        logging.info(f"Starting sanitization: {args.input} -> {args.output}")
        
        count = processor.process()
        
        logging.info(f"Sanitization completed. Total redactions performed: {count}")
    except LogVigilanteError as e:
        logging.error(f"Application Error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"Unexpected Runtime Failure: {e}", exc_info=True)
        sys.exit(2)

if __name__ == '__main__':
    main()