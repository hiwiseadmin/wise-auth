<?php
declare (strict_types = 1);

namespace wise\auth\command;

use think\console\Command;
use think\console\Input;
use think\console\Output;
use think\console\input\Argument;
use think\console\input\Option;
use wise\auth\facade\Rbac;
use wise\auth\traits\AdminCommandTrait;

/**
 * 超级管理员信息修改命令（统一入口）
 *
 * 使用示例：
 *   php think admin:modify [id] --password                       # 重置密码（交互输入）
 *   php think admin:modify [id] --password --new-password=xxx     # 重置密码（非交互）
 *   php think admin:modify [id] --username=new_name               # 修改用户名
 *
 * 自动化场景请配合 -n/--no-interaction + 显式参数：非交互模式下不再读 STDIN，
 * 缺参数直接报错并返回 1（不会挂起等待输入）。
 */
class AdminModify extends Command
{
    use AdminCommandTrait;

    protected function configure()
    {
        $this->setName('admin:modify')
            ->addArgument('id', Argument::OPTIONAL, '管理员ID（不指定时将自动检测）', null)
            ->addOption('password', 'p', Option::VALUE_NONE, '重置管理员密码')
            ->addOption('new-password', null, Option::VALUE_REQUIRED, '新密码（非交互/脚本场景使用，避免读 STDIN）')
            ->addOption('username', 'u', Option::VALUE_OPTIONAL, '修改管理员用户名（需提供新用户名）')
            ->setDescription('修改超级管理员信息（支持重置密码和修改用户名）');
    }

    /**
     * @return int 0=成功 1=失败
     */
    protected function execute(Input $input, Output $output)
    {
        if (PHP_SAPI !== 'cli') {
            $output->writeln("<error>该命令仅限CLI环境执行！</error>");
            return 1;
        }

        $interactive = $input->isInteractive();

        $resetPassword = $input->getOption('password');
        $newUsername = $input->getOption('username');
        $newPassword = $input->getOption('new-password');

        if (!$resetPassword && $newUsername === null) {
            if (!$interactive) {
                $output->writeln("<error>非交互模式（-n）下必须显式指定 --password 或 --username=<新用户名></error>");
                return 1;
            }

            $output->writeln("<comment>请指定操作类型：</comment>");
            $output->writeln("  <info>1</info>. 重置密码");
            $output->writeln("  <info>2</info>. 修改用户名");
            $output->writeln("  <info>0</info>. 取消");

            $choice = trim((string) $output->ask($input, '请输入序号：', '0'));
            if ($choice === '1') {
                $resetPassword = true;
            } elseif ($choice === '2') {
                $resetPassword = false;
            } else {
                $output->writeln("<info>操作已取消。</info>");
                return 0;
            }
        }

        $adminId = $input->getArgument('id');

        if ($adminId !== null && !is_numeric($adminId)) {
            $output->writeln("<error>管理员ID必须是数字！</error>");
            return 1;
        }

        if ($adminId === null) {
            $adminId = $this->selectAdmin($input, $output);
            if ($adminId === null) {
                $output->writeln("<error>未选择管理员或操作取消！</error>");
                return 1;
            }
        } else {
            $adminId = (int) $adminId;
        }

        $admin = $this->findAdmin($adminId);
        if (!$admin) {
            $output->writeln("<error>管理员不存在！</error>");
            return 1;
        }
        if (!Rbac::isSuperAdmin($adminId, $this->getAdminUserType())) {
            $output->writeln("<error>不能修改非超级管理员信息，请登录后台操作！</error>");
            return 1;
        }

        if ($resetPassword) {
            return $this->handleResetPassword($input, $output, $admin, is_string($newPassword) ? $newPassword : null);
        } else {
            return $this->handleChangeUsername($input, $output, $admin, $newUsername);
        }
    }

    /**
     * 处理重置密码
     *
     * @param Input       $input
     * @param Output      $output
     * @param array       $admin
     * @param string|null $prefillPassword 命令行预填的新密码
     * @return int
     */
    protected function handleResetPassword(Input $input, Output $output, array $admin, ?string $prefillPassword = null): int
    {
        $output->writeln("当前管理员用户名：<info>{$admin['username']}</info>");

        if ($prefillPassword !== null && $prefillPassword !== '') {
            $password = $prefillPassword;
        } elseif (!$input->isInteractive()) {
            $output->writeln("<error>非交互模式（-n）下无法读取密码，请使用 --new-password=<新密码></error>");
            return 1;
        } else {
            $password = trim((string) $output->askHidden($input, '请输入新密码（至少6位）：'));
        }

        if (strlen($password) < 6) {
            $output->writeln("<error>密码长度不能少于6位！</error>");
            return 1;
        }

        $options = config('check.password_hash.options', ['cost' => 12]);
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT, $options);

        $updated = $this->updateAdmin($admin['id'], [
            'password'    => $hashedPassword,
            'update_time' => date('Y-m-d H:i:s'),
        ]);

        if ($updated) {
            $output->writeln("<info>密码重置成功！</info>");
            return 0;
        }

        $output->writeln("<error>密码重置失败，请重试！</error>");
        return 1;
    }

    /**
     * 处理修改用户名
     *
     * @param Input       $input
     * @param Output      $output
     * @param array       $admin
     * @param string|null $prefillUsername 命令行预填的用户名
     * @return int
     */
    protected function handleChangeUsername(Input $input, Output $output, array $admin, ?string $prefillUsername): int
    {
        $output->writeln("当前用户名：<info>{$admin['username']}</info>");

        if ($prefillUsername !== null && $prefillUsername !== '') {
            $newUsername = $prefillUsername;
        } elseif (!$input->isInteractive()) {
            $output->writeln("<error>非交互模式（-n）下无法读取用户名，请使用 --username=<新用户名></error>");
            return 1;
        } else {
            $newUsername = trim((string) $output->ask($input, '请输入新用户名：', ''));
        }

        if (empty($newUsername)) {
            $output->writeln("<error>用户名不能为空！</error>");
            return 1;
        }

        if ($this->adminUsernameExists($newUsername, $admin['id'])) {
            $output->writeln("<error>用户名已存在！</error>");
            return 1;
        }

        $updated = $this->updateAdmin($admin['id'], [
            'username'    => $newUsername,
            'update_time' => date('Y-m-d H:i:s'),
        ]);

        if ($updated) {
            $output->writeln("<info>用户名修改成功！新用户名：{$newUsername}</info>");
            return 0;
        }

        $output->writeln("<error>用户名修改失败！</error>");
        return 1;
    }
}
