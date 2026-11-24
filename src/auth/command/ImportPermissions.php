<?php
/**
 * 批量导入权限命令
 *
 * 使用：
 *   php think wise:auth:import --from=config
 *   php think wise:auth:import --from=attribute --dir=app/admin/controller
 *   php think wise:auth:import --from=json --file=permissions.json
 */
namespace wise\auth\command;

use think\console\Command;
use think\console\Input;
use think\console\input\Option;
use think\console\Output;
use wise\auth\model\Permission;

class ImportPermissions extends Command
{
    /**
     * 配置命令：从 config / Attribute / JSON 批量导入权限
     *
     * php think wise:auth:import --from=config|attribute|json [--dir=...] [--file=...]
     */
    protected function configure()
    {
        $this->setName('wise:auth:import')
            ->addOption('from', 'f', Option::VALUE_REQUIRED, '数据来源：config、attribute 或 json')
            ->addOption('dir', 'd', Option::VALUE_OPTIONAL, 'Attribute 扫描目录')
            ->addOption('file', null, Option::VALUE_OPTIONAL, 'JSON 文件路径')
            ->setDescription('从配置文件、控制器 Attribute 或 JSON 文件导入权限');
    }

    /**
     * @return int 0=成功 1=失败
     */
    protected function execute(Input $input, Output $output)
    {
        $source = $input->getOption('from');
        if (!in_array($source, ['config', 'attribute', 'json'])) {
            $output->writeln('<error>无效的数据来源，可选值：config、attribute、json</error>');
            return 1;
        }

        $count = 0;
        switch ($source) {
            case 'config':
                $permissions = config('wise-auth.permissions', []);
                $count = Permission::loadFromConfig($permissions);
                $output->writeln("<info>已从配置文件导入 {$count} 条权限</info>");
                break;

            case 'attribute':
                $dir = $input->getOption('dir');
                if (!$dir) {
                    $output->writeln('<error>请指定 --dir Attribute 扫描目录</error>');
                    return 1;
                }
                $registrar = app(\wise\auth\service\PermissionRegistrar::class);
                $config = app('config');
                $config->set([
                    'attribute_dirs'     => [$dir],
                    'permission_sources' => ['attribute'],
                ], 'wise-auth');
                $count = $registrar->register();
                $output->writeln("<info>已从 {$dir} 的 #[AuthPermission] 导入 {$count} 条权限</info>");
                break;

            case 'json':
                $file = $input->getOption('file');
                if (!$file || !file_exists($file)) {
                    $output->writeln('<error>请指定有效的 --file JSON 文件路径</error>');
                    return 1;
                }
                $json = file_get_contents($file);
                if ($json === false) {
                    $output->writeln('<error>无法读取 JSON 文件内容</error>');
                    return 1;
                }
                $permissions = json_decode($json, true);
                if (!is_array($permissions)) {
                    $output->writeln('<error>无效的 JSON 格式</error>');
                    return 1;
                }
                $count = Permission::loadFromConfig($permissions);
                $output->writeln("<info>已从 {$file} 导入 {$count} 条权限</info>");
                break;
        }

        $registrar = app(\wise\auth\service\PermissionRegistrar::class);
        $registrar->clearPermissionsCache();

        $output->writeln('<info>权限缓存已清除</info>');

        return 0;
    }
}
