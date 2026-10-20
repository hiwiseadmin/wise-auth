<?php
/**
 * 管理员命令辅助 Trait
 *
 * 提供密码修改命令中 Admin 表名/模型名的统一读取入口，
 * 避免命令中硬编码 \app\admin\model\Admin 或表名。
 *
 * 优先级：
 *   1. wise-auth.user_models.admin — 管理员用户类型专用模型
 *   2. wise-auth.default_user_model — 默认用户模型
 *   3. 'admins' 表名兜底（兼容旧版）
 */
namespace wise\auth\traits;

use think\facade\Db;

trait AdminCommandTrait
{
    /**
     * 获取管理员表名
     *
     * @return string
     */
    protected function getAdminTable(): string
    {
        $modelClass = $this->getAdminModelClass();

        if ($modelClass && class_exists($modelClass)) {
            $instance = new $modelClass();
            if (method_exists($instance, 'getName')) {
                return $instance->getName();
            }
            if (property_exists($instance, 'table')) {
                return $instance->table;
            }
        }

        return 'admins';
    }

    /**
     * 获取管理员模型类名（FQCN）
     *
     * @return string|null
     */
    protected function getAdminModelClass(): ?string
    {
        return config('wise-auth.user_models.admin')
            ?? config('wise-auth.default_user_model');
    }

    /**
     * 获取管理员用户类型标识
     *
     * @return string
     */
    protected function getAdminUserType(): string
    {
        return 'admin';
    }

    /**
     * 查询管理员
     *
     * @param int|string $id
     * @return array|null
     */
    protected function findAdmin($id): ?array
    {
        $modelClass = $this->getAdminModelClass();

        if ($modelClass && class_exists($modelClass)) {
            $admin = $modelClass::find($id);
            if ($admin) {
                return $admin->toArray();
            }
            return null;
        }

        return Db::name($this->getAdminTable())->where('id', $id)->find();
    }

    /**
     * 更新管理员
     *
     * @param int|string $id
     * @param array      $data
     * @return bool
     */
    protected function updateAdmin($id, array $data): bool
    {
        $modelClass = $this->getAdminModelClass();

        if ($modelClass && class_exists($modelClass)) {
            $admin = $modelClass::find($id);
            if ($admin) {
                return $admin->save($data);
            }
            return false;
        }

        return (bool) Db::name($this->getAdminTable())
            ->where('id', $id)
            ->update($data);
    }

    /**
     * 查询超级管理员列表
     *
     * @param array $adminIds
     * @return array
     */
    protected function selectAdminsByIds(array $adminIds): array
    {
        $modelClass = $this->getAdminModelClass();

        if ($modelClass && class_exists($modelClass)) {
            return $modelClass::whereIn('id', $adminIds)
                ->order('id', 'asc')
                ->select()
                ->toArray();
        }

        return Db::name($this->getAdminTable())
            ->whereIn('id', $adminIds)
            ->order('id', 'asc')
            ->select()
            ->toArray();
    }

    /**
     * 根据用户名检查是否存在（排除指定 ID）
     *
     * @param string    $username
     * @param int|string $excludeId
     * @return bool
     */
    protected function adminUsernameExists(string $username, $excludeId): bool
    {
        $modelClass = $this->getAdminModelClass();

        if ($modelClass && class_exists($modelClass)) {
            return $modelClass::where('username', $username)
                ->where('id', '<>', $excludeId)
                ->count() > 0;
        }

        return Db::name($this->getAdminTable())
            ->where('username', $username)
            ->where('id', '<>', $excludeId)
            ->count() > 0;
    }

    /**
     * 交互式选择管理员（从 super_admin_ids 中列出）
     *
     * @param \think\console\Output $output
     * @return int|null 返回选中的管理员ID，取消则返回 null
     */
    protected function selectAdmin(\think\console\Output $output): ?int
    {
        $adminIds = config('wise-auth.super_admin_ids', []);
        if (empty($adminIds)) {
            $output->writeln("<error>没有找到任何管理员（请检查 wise-auth.super_admin_ids 配置）！</error>");
            return null;
        }

        $admins = $this->selectAdminsByIds($adminIds);
        if (empty($admins)) {
            $output->writeln("<error>没有找到任何管理员！</error>");
            return null;
        }

        $count = count($admins);
        if ($count == 1) {
            $admin = $admins[0];
            $output->writeln("<info>系统中只有一位管理员，将自动选中：ID: {$admin['id']}, 用户名: {$admin['username']}</info>");
            return (int) $admin['id'];
        }

        $output->writeln("<comment>发现多个管理员，请选择：</comment>");
        $options = [];
        foreach ($admins as $index => $admin) {
            $num = $index + 1;
            $output->writeln("  <info>{$num}</info>. ID: {$admin['id']}, 用户名: {$admin['username']}");
            $options[$num] = $admin['id'];
        }
        $output->writeln("  <info>0</info>. 取消操作");

        return $this->readChoice($output, $options, $count);
    }

    /**
     * 读取用户选择序号
     *
     * @param \think\console\Output $output
     * @param array $options 序号→ID 映射
     * @param int   $count   选项总数
     * @return int|null
     */
    private function readChoice(\think\console\Output $output, array $options, int $count): ?int
    {
        $output->writeln("请输入序号（0-{$count}）：");
        $rawInput = fgets(STDIN);
        if ($rawInput === false) {
            $output->writeln("<error>读取输入失败！</error>");
            return null;
        }
        $inputLine = trim($rawInput);

        if (!ctype_digit($inputLine)) {
            $output->writeln("<error>请输入有效的数字序号！</error>");
            return null;
        }

        $choice = (int) $inputLine;
        if ($choice === 0) {
            return null;
        }
        if (!isset($options[$choice])) {
            $output->writeln("<error>无效的序号！</error>");
            return null;
        }

        return $options[$choice];
    }
}
