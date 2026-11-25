<?php
declare(strict_types=1);

namespace wise\login\command;

use think\console\Command;
use think\console\Input;
use think\console\input\Option;
use think\console\Output;
use wise\login\lock\LoginLockManager;

/**
 * 解锁指定用户名
 *
 * 使用方法：
 *   php think wise:login:unlock --username=alice
 *   php think wise:login:unlock --username=alice --ip=192.168.1.10
 *   php think wise:login:unlock --all
 */
class Unlock extends Command
{
    protected function configure()
    {
        $this->setName('wise:login:unlock')
            ->setDescription('解锁用户账户（重置失败尝试和锁定状态）')
            ->addOption('username', 'u', Option::VALUE_REQUIRED, '要解锁的用户名')
            ->addOption('ip', 'i', Option::VALUE_OPTIONAL, '要解锁的 IP 地址（用于 IP+用户 作用域）')
            ->addOption('all', 'a', Option::VALUE_NONE, '强制解锁全部锁定键（仅限 redis/缓存存储）');
    }

    protected function execute(Input $input, Output $output): int
    {
        $output->writeln('<info>WiseAdmin 登录安全 — 解锁</info>');

        $lm = app(LoginLockManager::class);

        if ($input->getOption('all')) {
            $count = $lm->forceUnlockAll();
            $output->writeln("<info>已强制解锁，清除键数：{$count}</info>");
            return 0;
        }

        $username = (string) $input->getOption('username');
        if ($username === '') {
            $output->writeln('<error>错误：必须提供 --username 或 --all</error>');
            return 1;
        }

        $ip = (string) ($input->getOption('ip') ?? '');

        if ($ip === '') {
            $count = $lm->unlockByUsername($username);
            $output->writeln("<info>已按用户名解锁：{$username}（影响键数：{$count}）</info>");
        } else {
            $lm->unlock($username, $ip);
            $output->writeln("<info>已解锁：{$username} @ {$ip}</info>");
        }

        return 0;
    }
}
