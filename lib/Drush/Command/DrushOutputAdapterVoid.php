<?php

/**
 * @file
 * Definition of Drush\Command\DrushOutputAdapterVoid.
 */

namespace Drush\Command;

use Symfony\Component\Console\Output\Output;

/**
 * DrushOutputAdapter for PHP 7.1 and newer. Symfony Console 7 and 8 declare
 * doWrite(string $message, bool $newline): void; a method that keeps its
 * parameters untyped and returns void extends that and every older or
 * untyped Output too. drush_output_adapter() picks it; DrushOutputAdapter
 * keeps the untyped method PHP 5.6 and 7.0 need.
 */
class DrushOutputAdapterVoid extends Output {
    protected function doWrite($message, $newline): void
    {
        drush_print($message, 0, null, $newline);
    }
}
