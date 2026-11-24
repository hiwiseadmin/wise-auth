<?php
declare (strict_types = 1);

namespace wise\login\command;

use think\console\Command;
use think\console\Input;
use think\console\input\Argument;
use think\console\input\Option;
use think\console\Output;
use think\facade\Db;
use wise\login\lock\LoginLockManager;

/**
 * 清除登录失败次数 / 解除锁定（CLI）
 *
 * 用法：
 *   php think admin:clearfailures --all            # 全量清除（计数 + 锁标记）
 *   php think admin:clearfailures 3                # 按管理员 ID 清除
 *   php think admin:clearfailures --username=alice # 按用户名清除
 */
class ClearLoginFailures extends Command
{
    protected function configure(): void
    {
        $this->setName('admin:clearfailures')
            ->addArgument('id', Argument::OPTIONAL, '管理员 ID（与 --username / --all 三选一）', null)
            ->addOption('username', 'u', Option::VALUE_REQUIRED, '按用户名清除（适用于非管理员账号）')
            ->addOption('all', 'a', Option::VALUE_NONE, '全量清除所有失败计数与锁定标记')
            ->setDescription('清除登录失败次数并解锁（按 ID / 用户名 / 全量）');
    }

    protected function execute(Input $input, Output $output): int
    {
        if (PHP_SAPI !== 'cli') {
            $output->writeln('<error>该命令仅限 CLI 环境执行！</error>');
            return 1;
        }

        $lock  = app(LoginLockManager::class);
        $store = (string) config('wise-auth.login.failed_attempts.store', 'cache');

        $adminId  = $input->getArgument('id');
        $username = (string) ($input->getOption('username') ?? '');
        $all      = (bool) $input->getOption('all');

        if ($all) {
            $count = $lock->forceUnlockAll();
            $output->writeln("<info>已全量清除（存储：{$store}），记录数：{$count}</info>");

            if ($count === 0 && $store === 'cache') {
                $output->writeln(
                    '<comment>提示：当前 failed_attempts.store = cache，缓存驱动无法枚举键，'
                    . '因此无法全量清除。请改用 --username=<用户名> 逐个清除，'
                    . '或把存储切换为 database / redis 后再试。</comment>'
                );
            }

            return 0;
        }

        if ($username !== '') {
            $count = $lock->unlockByUsername($username);
            $output->writeln("<info>已清除用户名 {$username} 的失败记录，记录数：{$count}</info>");
            return 0;
        }

        if ($adminId === null) {
            $output->writeln('<error>请指定管理员 ID、--username 或 --all 三者之一。</error>');
            $output->writeln('用法示例：');
            $output->writeln('  php think admin:clearfailures --all');
            $output->writeln('  php think admin:clearfailures 3');
            $output->writeln('  php think admin:clearfailures --username=alice');
            return 1;
        }

        if (!ctype_digit((string) $adminId)) {
            $output->writeln('<error>管理员 ID 必须是数字！</error>');
            return 1;
        }

        $adminId = (int) $adminId;

        $admin = Db::name('admins')->field('id, username')->where('id', $adminId)->find();
        if (!$admin) {
            $output->writeln("<error>管理员不存在：ID {$adminId}</error>");
            return 1;
        }

        $count = $lock->unlockByUsername((string) $admin['username']);

        $output->writeln(
            "<info>已清除管理员 {$admin['username']}（ID {$adminId}）的失败记录，"
            . "记录数：{$count}</info>"
        );

        return 0;
    }
}
