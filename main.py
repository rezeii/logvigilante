import argparse
import re
import sys
import logging
import pathlib
import os
import tempfile
from typing import List, Pattern, Final

class LogVigilanteError(Exception): """Base exception for the LogVigilante domain."""

class ConfigurationError(LogVigilanteError): """Raised during initialization due to invalid parameters or environment."""

class ProcessingError(LogVigilanteError): """Raised during active stream processing due to I/O or system interrupts."""

class LogProcessor:
    """
    A high-integrity log sanitization engine implementing atomic writes and O(1) memory streaming.

    The processor ensures data integrity by writing to a temporary file in the destination 
    directory and performing an atomic rename upon successful completion. This prevents 
    leaving truncated files in the event of a system crash or disk exhaustion.

    Attributes:
        BUFFER_SIZE (int): 64KB chunk size for optimized I/O buffering.
    """
    BUFFER_SIZE: Final[int] = 65536

    def __init__(self, input_path: str, output_path: str, patterns: List[str], mask_char: str = "*"):
        """
        Initializes the processor with validated configuration.

        :param input_path: Source log file path.
        :param output_path: Destination for sanitized output.
        :param patterns: Regex strings to redact.
        :param mask_char: Single character for masking. Defaults to '*'.
        :raises ConfigurationError: If paths are invalid, permissions are missing, or regex is malformed.
        """
        self.input_path = pathlib.Path(input_path).resolve()
        self.output_path = pathlib.Path(output_path).resolve()
        
        if len(mask_char) != 1:
            raise ConfigurationError(f"mask_char must be exactly 1 character, got: {len(mask_char)}")
        self.mask_char = mask_char
        
        self.patterns = self._compile_patterns(patterns)
        self.redaction_count = 0
        self._validate_environment()

    def _compile_patterns(self, patterns: List[str]) -> List[Pattern]:
        """Compiles regex strings into re.Pattern objects with error catching."""
        if not patterns:
            raise ConfigurationError("No redaction patterns provided.")
        
        compiled = []
        for p in patterns:
            try:
                compiled.append(re.compile(p))
            except re.error as e:
                raise ConfigurationError(f"Regex compilation failed for '{p}': {e}")
        return compiled

    def _validate_environment(self):
        """
        Validates filesystem state using cross-platform access checks.
        Ensures input is readable and output directory is writable/executable.
        """
        if not self.input_path.is_file():
            raise ConfigurationError(f"Input source is missing or not a file: {self.input_path}")
        
        if not os.access(self.input_path, os.R_OK):
            raise ConfigurationError(f"Read permission denied for input: {self.input_path}")

        if self.input_path == self.output_path:
            raise ConfigurationError("In-place editing is not supported. Input and Output must differ.")

        output_dir = self.output_path.parent
        if not output_dir.exists():
            raise ConfigurationError(f"Output directory does not exist: {output_dir}")
        
        if not os.access(output_dir, os.W_OK | os.X_OK):
            raise ConfigurationError(f"Insufficient permissions to write in output directory: {output_dir}")

    def _mask_match(self, match: re.Match) -> str:
        """Callback for re.sub to increment metrics while masking."""
        self.redaction_count += 1
        return self.mask_char * len(match.group(0))

    def process(self) -> int:
        """
        Performs atomic line-by-line streaming redaction.

        Implementation Details:
        1. Opens input with 'replace' error handler to survive malformed encoding.
        2. Creates a temporary file in the target directory.
        3. Streams and redacts line by line.
        4. flushes and fsyncs the temp file to disk.
        5. Atomic move to final destination.

        :return: Total number of sensitive matches redacted.
        :raises ProcessingError: If I/O failure occurs or disk is full.
        """
        temp_fd, temp_path = tempfile.mkstemp(dir=self.output_path.parent, prefix=".vigilante_")
        line_no = 0
        try:
            with self.input_path.open('r', encoding='utf-8', errors='replace') as fin, \
                 os.fdopen(temp_fd, 'w', encoding='utf-8') as fout:
                
                for line in fin:
                    line_no += 1
                    sanitized = line
                    for pattern in self.patterns:
                        sanitized = pattern.sub(self._mask_match, sanitized)
                    fout.write(sanitized)
                
                fout.flush()
                os.fsync(fout.fileno())

            os.replace(temp_path, self.output_path)
            return self.redaction_count

        except Exception as e:
            if os.path.exists(temp_path):
                try: os.remove(temp_path)
                except: pass
            raise ProcessingError(f"Streaming failure at line {line_no}: {e}")

def main():
    parser = argparse.ArgumentParser(description="LogVigilante: Industrial-Grade Log Masking")
    parser.add_argument("-i", "--input", required=True, help="Path to source log")
    parser.add_argument("-o", "--output", required=True, help="Path to destination log")
    parser.add_argument("-p", "--patterns", nargs='+', default=[r"\b\d{4}-\d{4}-\d{4}-\d{4}\b"], help="Regexes to mask")
    parser.add_argument("-m", "--mask-char", default="*", help="Single masking character")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

    try:
        proc = LogProcessor(args.input, args.output, args.patterns, args.mask_char)
        logging.info(f"Processing: {proc.input_path} -> {proc.output_path}")
        count = proc.process()
        logging.info(f"Success. Total redactions: {count}")
    except LogVigilanteError as e:
        logging.error(f"Business Logic Failure: {e}")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"System Fault: {e}", exc_info=True)
        sys.exit(2)

if __name__ == '__main__':
    main()