<?php
declare(strict_types=1);

namespace wise\login\command;

use think\console\Command;
use think\console\Input;
use think\console\Output;
use think\facade\Db;
use wise\support\context\ContextualLogger;

/**
 * 2FA 恢复命令 — 管理员重置用户双因素认证＼�
 *
 * 用法：
 *   php think wise:login:recovery --user=admin --type=admin
 *   php think wise:login:recovery --user-id=1 --type=admin
 *   php think wise:login:recovery --list --type=admin
 *
 * 功能：
 *   --reset：重置指定用户的 TOTP 配置（清除密钥/备份码/恢复码，禁用 2FA）
 *   --list：列出所有已启用 2FA 的用户
 */
class Recovery extends Command
{
    protected function configure(): void
    {
        $this->setName('wise:login:recovery')
            ->addOption('user', null, \think\console\input\Option::VALUE_OPTIONAL, '用户名（备用标识）')
            ->addOption('user-id', null, \think\console\input\Option::VALUE_OPTIONAL, '用户 ID')
            ->addOption('type', null, \think\console\input\Option::VALUE_OPTIONAL, '用户类型（admin/member）', 'admin')
            ->addOption('reset', null, \think\console\input\Option::VALUE_NONE, '重置该用户的 2FA')
            ->addOption('list', null, \think\console\input\Option::VALUE_NONE, '列出所有已启用 2FA 的用户')
            ->setDescription('管理员重置用户双因素认证（P2-#17）');
    }

    protected function execute(Input $input, Output $output): int
    {
        $table = 'auth_totp_configs';
        $type = $input->getOption('type') ?: 'admin';

        if ($input->getOption('list')) {
            $rows = Db::name($table)
                ->where('user_type', $type)
                ->where('totp_enabled', 1)
                ->select()
                ->toArray();

            if (empty($rows)) {
                $output->writeln('<info>没有找到已启用 2FA 的用户</info>');
                return 0;
            }

            $output->writeln("<info>用户类型: {$type}，已启用 2FA 用户列表：</info>");
            $output->writeln('────────────────────────────────────────────');
            foreach ($rows as $row) {
                $backupCount = $this->countCodes($row['totp_backup_codes'] ?? '');
                $recoveryCount = $this->countCodes($row['totp_recovery_codes'] ?? '');
                $output->writeln(sprintf(
                    '  ID: %-6d | 剩余备份码: %d | 剩余恢复码: %d | 启用时间: %s',
                    $row['user_id'],
                    $backupCount,
                    $recoveryCount,
                    $row['update_time'] ?? $row['create_time'] ?? '未知'
                ));
            }
            $output->writeln('────────────────────────────────────────────');
            $output->writeln("<info>共 " . count($rows) . " 个用户</info>");
            return 0;
        }

        $userId = $input->getOption('user-id');
        $username = $input->getOption('user');

        if (empty($userId) && empty($username)) {
            $output->writeln('<error>请提供 --user 或 --user-id 参数</error>');
            return 1;
        }

        $query = Db::name($table)->where('user_type', $type);

        if ($userId) {
            $query->where('user_id', (int) $userId);
        } else {
            $output->writeln("<comment>按用户名查找需要先在 totp_config 表中有记录。如果用户尚未设置过 2FA，请使用 --user-id 指定。</comment>");
            $output->writeln("<comment>或者使用 --list 查看所有已启用用户列表。</comment>");
            $output->writeln('');
            $output->writeln("<info>请提供该用户的数字 ID（使用 --user-id）：</info>");
            $output->writeln("  php think wise:login:recovery --user-id=<ID> --type={$type} --reset");
            return 1;
        }

        $record = $query->find();
        if (empty($record)) {
            $output->writeln('<comment>该用户未设置过 2FA，无需重置</comment>');
            return 0;
        }

        if (!$input->getOption('reset')) {
            $output->writeln(sprintf(
                '<comment>即将重置用户 #%d (%s) 的 2FA 配置</comment>',
                $record['user_id'],
                $type
            ));
            $output->writeln('<comment>这将：</comment>');
            $output->writeln('  - 禁用 2FA');
            $output->writeln('  - 清除 TOTP 密钥');
            $output->writeln('  - 清除所有备份码和恢复码');
            $output->writeln('<comment>添加 --reset 确认执行</comment>');
            return 0;
        }

        Db::name($table)
            ->where('user_type', $type)
            ->where('user_id', (int) $record['user_id'])
            ->update([
                'totp_enabled'        => 0,
                'totp_secret'         => null,
                'totp_backup_codes'   => null,
                'totp_recovery_codes' => null,
                'update_time'          => date('Y-m-d H:i:s'),
            ]);

        ContextualLogger::info('[RecoveryCommand] 管理员已重置 2FA', [
            'user_id'   => $record['user_id'],
            'user_type' => $type,
            'operator'  => 'cli',
        ]);

        $output->writeln(sprintf(
            '<info>✅ 用户 #%d (%s) 的 2FA 已成功重置</info>',
            $record['user_id'],
            $type
        ));
        $output->writeln('<comment>该用户下次登录时将不再需要 2FA，可以重新设置。</comment>');
        return 0;
    }

    protected function countCodes(?string $json): int
    {
        if (empty($json)) {
            return 0;
        }
        $data = json_decode($json, true);
        return is_array($data) ? count($data) : 0;
    }
}
