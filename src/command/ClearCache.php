<?php
/**
 * 清除权限缓存命令
 *
 * 使用：
 *   php think wise:auth:clear // 清除所有缓存
 *   php think wise:auth:clear --user=123456 --type=admin // 清除指定用户缓存
 * 
 */
namespace wise\auth\command;

use think\console\Command;
use think\console\Input;
use think\console\Output;

class ClearCache extends Command
{
    protected function configure()
    {
        $this->setName('wise:auth:clear')
            ->setDescription('清除 WiseAuth 全部权限缓存')
            ->addOption('user', 'u', \think\console\input\Option::VALUE_OPTIONAL, '清除指定用户ID的缓存')
            ->addOption('type', 't', \think\console\input\Option::VALUE_OPTIONAL, '用户类型（默认：admin）', 'admin');
    }

    protected function execute(Input $input, Output $output)
    {
        $manager = app(\wise\auth\service\RbacManager::class);
        $registrar = app(\wise\auth\service\PermissionRegistrar::class);

        $userId = $input->getOption('user');

        if ($userId) {
            $userType = $input->getOption('type', 'admin');
            $manager->clearUserCache($userId, $userType);
            $output->writeln("<info>已清除用户权限缓存：{$userType}:{$userId}</info>");
        } else {
            $manager->clearAllCache();
            $registrar->clearPermissionsCache();
            $output->writeln('<info>已清除全部 WiseAuth 缓存。</info>');
        }
    }
}
