<?php

/**
 * @file
 * Definition of Drush\Command\DrushInputAdapter12.
 */

namespace Drush\Command;

use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputDefinition;

/**
 * DrushInputAdapter for Drupal 12, whose Symfony declares a return type on
 * every InputInterface method and adds __toString(): an implementation must
 * repeat them. DrushInputAdapter keeps the untyped methods the older cores
 * and their PHP versions need.
 */
class DrushInputAdapter12 implements InputInterface
{
    protected $arguments;
    protected $options;
    protected $interactive;

    public function __construct($arguments, $options, $command = false, $interactive = true)
    {
        $this->arguments = $arguments;
        $this->options = $options;

        // If a command name is provided as a parameter, then push
        // it onto the front of the arguments list as a service
        if ($command) {
            $this->arguments = array_merge(
                [ 'command' => $command ],
                $this->arguments
            );
        }
        $this->interactive = $interactive;
    }

    /**
     *  {@inheritdoc}
     */
    public function getFirstArgument(): ?string
    {
        $first = reset($this->arguments);
        return is_scalar($first) ? (string) $first : null;
    }

    /**
     * {@inheritdoc}
     */
    public function hasParameterOption($values, $onlyParams = false): bool
    {
        $values = (array) $values;

        foreach ($values as $value) {
            if (array_key_exists($value, $this->options)) {
                return true;
            }
        }

        return false;
    }

    /**
     *  {@inheritdoc}
     */
    public function getParameterOption($values, $default = false, $onlyParams = false): mixed
    {
        $values = (array) $values;

        foreach ($values as $value) {
            if (array_key_exists($value, $this->options)) {
                return $this->getOption($value);
            }
        }

        return $default;
    }

    /**
     *  {@inheritdoc}
     */
    public function bind(InputDefinition $definition): void
    {
        // no-op: this class exists to avoid validation
    }

    /**
     *  {@inheritdoc}
     */
    public function validate(): void
    {
        // no-op: this class exists to avoid validation
    }

    /**
     *  {@inheritdoc}
     */
    public function getArguments(): array
    {
        return $this->arguments;
    }

    /**
     *  {@inheritdoc}
     */
    public function getArgument($name): mixed
    {
        return isset($this->arguments[$name]) ? $this->arguments[$name] : '';
    }

    /**
     *  {@inheritdoc}
     */
    public function setArgument($name, $value): void
    {
        $this->arguments[$name] = $value;
    }

    /**
     *  {@inheritdoc}
     */
    public function hasArgument($name): bool
    {
        return isset($this->arguments[$name]);
    }

    /**
     *  {@inheritdoc}
     */
    public function getOptions(): array
    {
        return $this->options;
    }

    /**
     *  {@inheritdoc}
     */
    public function getOption($name): mixed
    {
        return $this->options[$name];
    }

    /**
     *  {@inheritdoc}
     */
    public function setOption($name, $value): void
    {
        $this->options[$name] = $value;
    }

    /**
     *  {@inheritdoc}
     */
    public function hasOption($name): bool
    {
        return isset($this->options[$name]);
    }

    /**
     *  {@inheritdoc}
     */
    public function isInteractive(): bool
    {
        return (bool) $this->interactive;
    }

    /**
     *  {@inheritdoc}
     */
    public function setInteractive($interactive): void
    {
        $this->interactive = $interactive;
    }

    /**
     * The arguments as one line, as a command line would carry them.
     */
    public function __toString(): string
    {
        $parts = [];
        foreach ($this->arguments as $argument) {
            if (is_scalar($argument)) {
                $parts[] = (string) $argument;
            }
        }
        return implode(' ', $parts);
    }
}
