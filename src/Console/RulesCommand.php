<?php

declare(strict_types=1);

namespace Plumbline\Console;

use Plumbline\Plumbline;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'rules', description: 'List the available rules')]
final class RulesCommand extends Command
{
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $table = new Table($output);
        $table->setHeaders(['ID', 'Severity', 'CWE', 'Title']);
        foreach (Plumbline::defaultRules() as $rule) {
            $meta = $rule->meta();
            $table->addRow([$meta->id, $meta->severity->value, $meta->cwe, $meta->title]);
        }
        $table->render();

        return 0;
    }
}
