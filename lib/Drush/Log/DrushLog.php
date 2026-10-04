<?php

/**
 * @file
 * Contains \Drush\Log\DrushLog.
 *
 * This class is only used to convert logging calls made
 * inside of Drupal into a logging format that is usable
 * by Drush.  This code is ONLY usable within the context
 * of a bootstrapped Drupal 8 site.
 *
 * See Drush\Log\Logger for our actuall LoggerInterface
 * implementation, that does the work of logging messages
 * that originate from Drush.
 */

namespace Drush\Log;

use Drupal\Core\Logger\LogMessageParserInterface;
use Drupal\Core\Logger\RfcLogLevel;
use Psr\Log\LoggerInterface;

/**
 * Redirects Drupal logging messages to Drush log.
 *
 * Note that Drupal extends the LoggerInterface, and
 * needlessly replaces Psr\Log\LogLevels with Drupal\Core\Logger\RfcLogLevel.
 * Doing this arguably violates the Psr\Log contract,
 * but we can't help that here -- we just need to convert back.
 *
 * The level methods are declared here, untyped, with the RfcLogLevel each
 * one maps to in core's RfcLoggerTrait, rather than taken from that trait:
 * since Drupal 10 the trait's abstract log() is typed with ': void', which
 * an untyped log() cannot match, while a de-typed core and Drupal 8 and 9
 * have it untyped. An untyped class matches the psr/log 1 interface Drush
 * binds below PHP 8.0 and the psr/log 2.0 one it binds from 8.0 on, with
 * any core.
 */
class DrushLog implements LoggerInterface {

  /**
   * The message's placeholders parser.
   *
   * @var \Drupal\Core\Logger\LogMessageParserInterface
   */
  protected $parser;

  /**
   * The logger that messages will be passed through to.
   */
  protected $logger;

  /**
   * Constructs a DrushLog object.
   *
   * @param \Drupal\Core\Logger\LogMessageParserInterface $parser
   *   The parser to use when extracting message variables.
   */
  public function __construct(LogMessageParserInterface $parser, LoggerInterface $logger) {
    $this->parser = $parser;
    $this->logger = $logger;
  }

  /**
   * {@inheritdoc}
   */
  public function emergency($message, array $context = array()) {
    $this->log(RfcLogLevel::EMERGENCY, $message, $context);
  }

  /**
   * {@inheritdoc}
   */
  public function alert($message, array $context = array()) {
    $this->log(RfcLogLevel::ALERT, $message, $context);
  }

  /**
   * {@inheritdoc}
   */
  public function critical($message, array $context = array()) {
    $this->log(RfcLogLevel::CRITICAL, $message, $context);
  }

  /**
   * {@inheritdoc}
   */
  public function error($message, array $context = array()) {
    $this->log(RfcLogLevel::ERROR, $message, $context);
  }

  /**
   * {@inheritdoc}
   */
  public function warning($message, array $context = array()) {
    $this->log(RfcLogLevel::WARNING, $message, $context);
  }

  /**
   * {@inheritdoc}
   */
  public function notice($message, array $context = array()) {
    $this->log(RfcLogLevel::NOTICE, $message, $context);
  }

  /**
   * {@inheritdoc}
   */
  public function info($message, array $context = array()) {
    $this->log(RfcLogLevel::INFO, $message, $context);
  }

  /**
   * {@inheritdoc}
   */
  public function debug($message, array $context = array()) {
    $this->log(RfcLogLevel::DEBUG, $message, $context);
  }

  /**
   * {@inheritdoc}
   */
  public function log($level, $message, array $context = array()) {
    // Translate the RFC logging levels into their Drush counterparts, more or
    // less.
    // @todo ALERT, CRITICAL and EMERGENCY are considered show-stopping errors,
    // and they should cause Drush to exit or panic. Not sure how to handle this,
    // though.
    switch ($level) {
      case RfcLogLevel::ALERT:
      case RfcLogLevel::CRITICAL:
      case RfcLogLevel::EMERGENCY:
      case RfcLogLevel::ERROR:
        $error_type = LogLevel::ERROR;
        break;

      case RfcLogLevel::WARNING:
        $error_type = LogLevel::WARNING;
        break;

      // TODO: RfcLogLevel::DEBUG should be 'debug' rather than 'notice'?
      case RfcLogLevel::DEBUG:
      case RfcLogLevel::INFO:
      case RfcLogLevel::NOTICE:
        $error_type = LogLevel::NOTICE;
        break;

      // TODO: Unknown log levels that are not defined
      // in Psr\Log\LogLevel or Drush\Log\LogLevel SHOULD NOT be used.  See
      // https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-3-logger-interface.md
      // We should convert these to 'notice'.
      default:
        $error_type = $level;
        break;
    }

    // Populate the message placeholders and then replace them in the message.
    $message_placeholders = $this->parser->parseMessagePlaceholders($message, $context);

    // Filter out any placeholders that can not be cast to strings.
    $message_placeholders = array_filter($message_placeholders, function ($element) {
      return is_scalar($element) || is_callable([$element, '__toString']);
    });

    $message = empty($message_placeholders) ? $message : strtr($message, $message_placeholders);

    $this->logger->log($error_type, $message, $context);
  }

}
