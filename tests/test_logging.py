"""Tests for Hamburglar logging configuration.

This module contains tests for the logging setup functions defined in
hamburglar.core.logging, verifying that logging is properly configured
with Rich handler, appropriate log levels, and source context.
"""

from __future__ import annotations

import logging

from rich.logging import RichHandler

from hamburglar.core.logging import get_logger, setup_logging


class TestSetupLogging:
    """Tests for the setup_logging function."""

    def test_returns_logger_instance(self) -> None:
        """Test that setup_logging returns a Logger instance."""
        logger = setup_logging()
        assert isinstance(logger, logging.Logger)

    def test_logger_name_is_hamburglar(self) -> None:
        """Test that the logger is named 'hamburglar'."""
        logger = setup_logging()
        assert logger.name == "hamburglar"

    def test_verbose_false_sets_warning_level(self) -> None:
        """Test that verbose=False sets log level to WARNING."""
        logger = setup_logging(verbose=False)
        assert logger.level == logging.WARNING

    def test_verbose_true_sets_debug_level(self) -> None:
        """Test that verbose=True sets log level to DEBUG."""
        logger = setup_logging(verbose=True)
        assert logger.level == logging.DEBUG

    def test_has_rich_handler(self) -> None:
        """Test that logger has a RichHandler attached."""
        logger = setup_logging()
        assert len(logger.handlers) >= 1
        assert any(isinstance(h, RichHandler) for h in logger.handlers)

    def test_no_duplicate_handlers_on_multiple_calls(self) -> None:
        """Test that calling setup_logging multiple times doesn't add duplicate handlers."""
        setup_logging(verbose=False)
        setup_logging(verbose=True)
        logger = setup_logging(verbose=False)
        # Should only have one handler
        assert len(logger.handlers) == 1

    def test_propagate_is_disabled(self) -> None:
        """Test that logger propagation is disabled to avoid duplicate messages."""
        logger = setup_logging()
        assert logger.propagate is False

    def test_handler_level_matches_logger_level_verbose(self) -> None:
        """Test that handler level matches logger level when verbose."""
        logger = setup_logging(verbose=True)
        handler = logger.handlers[0]
        assert handler.level == logging.DEBUG

    def test_handler_level_matches_logger_level_non_verbose(self) -> None:
        """Test that handler level matches logger level when not verbose."""
        logger = setup_logging(verbose=False)
        handler = logger.handlers[0]
        assert handler.level == logging.WARNING


class TestGetLogger:
    """Tests for the get_logger function."""

    def test_returns_logger_instance(self) -> None:
        """Test that get_logger returns a Logger instance."""
        logger = get_logger()
        assert isinstance(logger, logging.Logger)

    def test_returns_same_logger_as_setup_logging(self) -> None:
        """Test that get_logger returns the same logger configured by setup_logging."""
        setup_logger = setup_logging(verbose=True)
        get_logger_result = get_logger()
        assert setup_logger is get_logger_result

    def test_creates_default_logger_if_not_setup(self) -> None:
        """Test that get_logger creates a default logger if setup_logging wasn't called."""
        # Reset the module-level logger by re-importing
        import hamburglar.core.logging as log_module

        log_module._logger = None
        logger = get_logger()
        assert logger is not None
        assert isinstance(logger, logging.Logger)

    def test_logger_name_is_hamburglar(self) -> None:
        """Test that the logger from get_logger is named 'hamburglar'."""
        logger = get_logger()
        assert logger.name == "hamburglar"


class TestVerboseMode:
    """Tests for verbose mode logging behavior."""

    def test_debug_messages_logged_in_verbose_mode(self) -> None:
        """Test that debug messages are logged when verbose=True."""
        logger = setup_logging(verbose=True)
        # In verbose mode (DEBUG level), debug messages should be enabled
        assert logger.isEnabledFor(logging.DEBUG)

    def test_debug_messages_not_logged_in_non_verbose_mode(self) -> None:
        """Test that debug messages are not logged when verbose=False."""
        logger = setup_logging(verbose=False)
        # In non-verbose mode (WARNING level), debug messages should be disabled
        assert not logger.isEnabledFor(logging.DEBUG)

    def test_info_messages_logged_in_verbose_mode(self) -> None:
        """Test that info messages are logged when verbose=True."""
        logger = setup_logging(verbose=True)
        assert logger.isEnabledFor(logging.INFO)

    def test_info_messages_not_logged_in_non_verbose_mode(self) -> None:
        """Test that info messages are not logged when verbose=False."""
        logger = setup_logging(verbose=False)
        assert not logger.isEnabledFor(logging.INFO)

    def test_warning_messages_always_logged(self) -> None:
        """Test that warning messages are logged regardless of verbosity."""
        logger_verbose = setup_logging(verbose=True)
        logger_non_verbose = setup_logging(verbose=False)
        assert logger_verbose.isEnabledFor(logging.WARNING)
        assert logger_non_verbose.isEnabledFor(logging.WARNING)

    def test_error_messages_always_logged(self) -> None:
        """Test that error messages are logged regardless of verbosity."""
        logger_verbose = setup_logging(verbose=True)
        logger_non_verbose = setup_logging(verbose=False)
        assert logger_verbose.isEnabledFor(logging.ERROR)
        assert logger_non_verbose.isEnabledFor(logging.ERROR)


class TestRichHandlerConfiguration:
    """Tests for Rich handler configuration."""

    def test_rich_handler_has_console(self) -> None:
        """Test that Rich handler has a console attached."""
        logger = setup_logging()
        handler = next(h for h in logger.handlers if isinstance(h, RichHandler))
        assert handler.console is not None

    def test_rich_handler_has_rich_tracebacks(self) -> None:
        """Test that Rich handler is configured with rich tracebacks."""
        logger = setup_logging()
        handler = next(h for h in logger.handlers if isinstance(h, RichHandler))
        assert handler.rich_tracebacks is True

    def test_rich_handler_has_markup_enabled(self) -> None:
        """Test that Rich handler is configured with markup enabled."""
        logger = setup_logging()
        handler = next(h for h in logger.handlers if isinstance(h, RichHandler))
        assert handler.markup is True

    def test_rich_handler_has_formatter(self) -> None:
        """Test that Rich handler has a formatter set."""
        logger = setup_logging()
        handler = next(h for h in logger.handlers if isinstance(h, RichHandler))
        assert handler.formatter is not None


class TestLogMessageContent:
    """Tests for log message content and formatting."""

    def test_can_log_debug_message(self) -> None:
        """Test that debug messages can be logged without error."""
        logger = setup_logging(verbose=True)
        # Should not raise any exceptions
        logger.debug("Debug message for testing")

    def test_can_log_info_message(self) -> None:
        """Test that info messages can be logged without error."""
        logger = setup_logging(verbose=True)
        logger.info("Info message for testing")

    def test_can_log_warning_message(self) -> None:
        """Test that warning messages can be logged without error."""
        logger = setup_logging()
        logger.warning("Warning message for testing")

    def test_can_log_error_message(self) -> None:
        """Test that error messages can be logged without error."""
        logger = setup_logging()
        logger.error("Error message for testing")

    def test_can_log_with_format_arguments(self) -> None:
        """Test that log messages with format arguments work correctly."""
        logger = setup_logging(verbose=True)
        logger.debug("Processing file %s with size %d", "test.txt", 1024)

    def test_can_log_exception_info(self) -> None:
        """Test that exception info can be logged."""
        logger = setup_logging()
        try:
            raise ValueError("Test exception")
        except ValueError:
            logger.exception("Caught an error")


class TestLogOutputFormat:
    """Tests for verifying log output contains timestamps and source context."""

    def test_rich_handler_shows_time(self) -> None:
        """Test that the Rich handler is configured to show timestamps."""
        logger = setup_logging(verbose=True)
        handler = next(h for h in logger.handlers if isinstance(h, RichHandler))
        # RichHandler stores show_time in _log_render
        assert handler._log_render.show_time is True

    def test_rich_handler_shows_path(self) -> None:
        """Test that the Rich handler is configured to show source path/context."""
        logger = setup_logging(verbose=True)
        handler = next(h for h in logger.handlers if isinstance(h, RichHandler))
        # RichHandler stores show_path in _log_render
        assert handler._log_render.show_path is True

    def test_rich_handler_shows_level(self) -> None:
        """Test that the Rich handler is configured to show log level."""
        logger = setup_logging(verbose=True)
        handler = next(h for h in logger.handlers if isinstance(h, RichHandler))
        # RichHandler stores show_level in _log_render
        assert handler._log_render.show_level is True

    def test_date_format_includes_time(self) -> None:
        """Test that the date format string includes time components."""
        from hamburglar.core.logging import DATE_FORMAT

        # The format should contain time directive (%X = locale's appropriate time representation)
        assert "%X" in DATE_FORMAT or "%H" in DATE_FORMAT or "%T" in DATE_FORMAT

    def test_handler_formatter_has_date_format(self) -> None:
        """Test that the handler's formatter has a date format set."""
        logger = setup_logging(verbose=True)
        handler = next(h for h in logger.handlers if isinstance(h, RichHandler))
        # RichHandler sets the date format via the formatter
        assert handler.formatter is not None
        assert handler.formatter.datefmt is not None
        assert len(handler.formatter.datefmt) > 0

    def test_verbose_mode_produces_debug_output(self) -> None:
        """Test that verbose mode enables debug level logging output."""
        logger = setup_logging(verbose=True)
        # In verbose mode, DEBUG level should be enabled
        assert logger.level == logging.DEBUG
        assert logger.isEnabledFor(logging.DEBUG)
        # The handler should also be set to DEBUG
        handler = logger.handlers[0]
        assert handler.level == logging.DEBUG

    def test_quiet_mode_suppresses_info_output(self) -> None:
        """Test that quiet mode (non-verbose) suppresses info level output."""
        logger = setup_logging(verbose=False)
        # In quiet mode, INFO level should be suppressed
        assert logger.level == logging.WARNING
        assert not logger.isEnabledFor(logging.INFO)
        assert not logger.isEnabledFor(logging.DEBUG)
        # But WARNING and above should still be enabled
        assert logger.isEnabledFor(logging.WARNING)
        assert logger.isEnabledFor(logging.ERROR)

    def test_log_record_contains_source_file(self) -> None:
        """Test that log records include source file information."""
        logger = setup_logging(verbose=True)

        # Create a custom handler to capture log records
        captured_records: list[logging.LogRecord] = []

        class RecordCapture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                captured_records.append(record)

        capture_handler = RecordCapture()
        capture_handler.setLevel(logging.DEBUG)
        logger.addHandler(capture_handler)

        # Log a message
        logger.debug("Test message from source")

        # Verify the log record contains source context
        assert len(captured_records) == 1
        record = captured_records[0]
        # Log records should contain filename, lineno, and funcName
        assert record.filename == "test_logging.py"
        assert record.lineno > 0
        assert record.funcName == "test_log_record_contains_source_file"

        # Clean up
        logger.removeHandler(capture_handler)

    def test_log_record_contains_timestamp(self) -> None:
        """Test that log records include timestamp information."""
        import time

        logger = setup_logging(verbose=True)

        # Create a custom handler to capture log records
        captured_records: list[logging.LogRecord] = []

        class RecordCapture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                captured_records.append(record)

        capture_handler = RecordCapture()
        capture_handler.setLevel(logging.DEBUG)
        logger.addHandler(capture_handler)

        # Record time before logging
        before_time = time.time()
        logger.debug("Test message with timestamp")
        after_time = time.time()

        # Verify the log record contains timestamp
        assert len(captured_records) == 1
        record = captured_records[0]
        # Log records should contain created timestamp
        assert hasattr(record, "created")
        assert before_time <= record.created <= after_time

        # Clean up
        logger.removeHandler(capture_handler)
