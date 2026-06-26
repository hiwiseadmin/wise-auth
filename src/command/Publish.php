<?php
/**
 * WiseAuth 初始化命令
 *
 * 发布配置、执行迁移、注册权限等。
 *
 * 使用：php think wise:auth:publish
 */
namespace wise\auth\command;

use think\console\Command;
use think\console\Input;
use think\console\Output;
use think\console\input\Option;

class Publish extends Command
{
    protected function configure()
    {
        $this->setName('wise:auth:publish')
            ->setDescription('Publish config and migration files of wise-auth package')
            ->addOption('force', 'f', Option::VALUE_NONE, 'Force overwrite existing config');
    }

    protected function execute(Input $input, Output $output)
    {
        $force = $input->getOption('force');

        $output->writeln('');
        $output->writeln('<info>========================================</info>');
        $output->writeln('<info>wiseadmin/wise-auth - Initialization</info>');
        $output->writeln('<info>========================================</info>');
        $output->writeln('');

        // 1. 发布迁移文件
        $this->publishMigrations($output);

        // 2. 发布配置文件
        $this->publishConfig($output, $force);

        // 3. 注册权限
        $registrar = app(\wise\auth\service\PermissionRegistrar::class);
        $count = $registrar->register();
        $output->writeln('');
        $output->writeln("<info>Registered {$count} permission(s) from config/annotation.</info>");
        $output->writeln('');

        // 4. 提示初始化成功
        $output->writeln('<info>WiseAuth initialized successfully!</info>');

        // 5. 提示执行迁移
        $output->writeln('');
        $output->writeln('<info>Please run the following command to execute migrations:</info>');
        $output->writeln('<comment>  php think migrate:run</comment>');
        $output->writeln('');
    }

    /**
     * 发布迁移文件
     *
     * @param Output $output
     */
    protected function publishMigrations(Output $output): void
    {
        $sourceDir = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'database' . DIRECTORY_SEPARATOR . 'migrations';
        $targetDir = root_path() . 'database' . DIRECTORY_SEPARATOR . 'migrations';

        if (!is_dir($sourceDir)) {
            $output->writeln("<error>Error: Source migration directory not found: {$sourceDir}</error>");
        }

        if (!is_dir($targetDir)) {
            if (!@mkdir($targetDir, 0755, true)) {
                $output->writeln("<error>Error: Failed to create target directory: {$targetDir}</error>");
            }
        }

        $count = 0;
        $files = glob($sourceDir . DIRECTORY_SEPARATOR . '*.php') ?: [];
        foreach ($files as $file) {
            $name = basename($file);
            $dest = $targetDir . DIRECTORY_SEPARATOR . $name;
            if (file_exists($dest)) {
                $output->writeln("  - [skip] {$name}（exists)");
                continue;
            }
            if (!@copy($file, $dest)) {
                $output->writeln("  - <error>[fail]</error> {$name}");
                continue;
            }
            $output->writeln("  - <info>[ok]</info>   {$name}");
            $count++;
        }

        $output->writeln('');
        $output->writeln("<info>Published migration files: {$count} migration files to {$targetDir}</info>");
        $output->writeln('');
    }

    /**
     * 发布配置文件
     *
     * @param Output $output
     * @param bool   $force
     */
    protected function publishConfig(Output $output, bool $force): void
    {
        $source = dirname(__DIR__, 2) . '/config/wise-auth.php';
        $target = app()->getConfigPath() . 'wise-auth.php';

        if (file_exists($target) && !$force) {
            $output->writeln("<comment>Config file already exists at {$target}. Use --force to overwrite.</comment>");
            return;
        }

        if (copy($source, $target)) {
            $output->writeln("<info>Config published to: {$target}</info>");
        } else {
            $output->writeln("<error>Failed to publish config to: {$target}</error>");
        }
        $output->writeln('');
    }
}
