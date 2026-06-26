<?php
/**
 * 批量导入权限命令
 *
 * 使用：
 *   php think wise:auth:import --from=config
 *   php think wise:auth:import --from=annotation --dir=app/admin/controller
 *   php think wise:auth:import --from=json --file=permissions.json
 * 
 */
namespace wise\auth\command;

use think\console\Command;
use think\console\Input;
use think\console\Output;
use wise\auth\model\Permission;

class ImportPermissions extends Command
{
    protected function configure()
    {
        $this->setName('wise:auth:import')
            ->setDescription('从配置文件、注解或 JSON 文件导入权限')
            ->addOption('from', 'f', \think\console\input\Option::VALUE_REQUIRED, '数据来源：config、annotation 或 json')
            ->addOption('dir', 'd', \think\console\input\Option::VALUE_OPTIONAL, '注解扫描目录')
            ->addOption('file', null, \think\console\input\Option::VALUE_OPTIONAL, 'JSON 文件路径');
    }

    protected function execute(Input $input, Output $output)
    {
        $source = $input->getOption('from');
        if (!in_array($source, ['config', 'annotation', 'json'])) {
            $output->writeln('<error>无效的数据来源，可选值：config、annotation、json</error>');
            return;
        }

        $count = 0;
        switch ($source) {
            case 'config':
                $permissions = config('wise-auth.permissions', []);
                $count = Permission::loadFromConfig($permissions);
                $output->writeln("<info>已从配置文件导入 {$count} 条权限</info>");
                break;

            case 'annotation':
                $dir = $input->getOption('dir');
                if (!$dir) {
                    $output->writeln('<error>请指定 --dir 注解扫描目录</error>');
                    return;
                }
                $registrar = app(\wise\auth\service\PermissionRegistrar::class);
                // 设置扫描目录
                config(['wise-auth.annotation_dirs' => [$dir]], 'wise-auth');
                $count = $registrar->register();
                $output->writeln("<info>已从 {$dir} 注解导入 {$count} 条权限</info>");
                break;

            case 'json':
                $file = $input->getOption('file');
                if (!$file || !file_exists($file)) {
                    $output->writeln('<error>请指定有效的 --file JSON 文件路径</error>');
                    return;
                }
                $json = file_get_contents($file);
                $permissions = json_decode($json, true);
                if (!is_array($permissions)) {
                    $output->writeln('<error>无效的 JSON 格式</error>');
                    return;
                }
                $count = Permission::loadFromConfig($permissions);
                $output->writeln("<info>已从 {$file} 导入 {$count} 条权限</info>");
                break;
        }

        // 清除缓存
        $registrar = app(\wise\auth\service\PermissionRegistrar::class);
        $registrar->clearPermissionsCache();

        $output->writeln('<info>权限缓存已清除</info>');
    }
}
