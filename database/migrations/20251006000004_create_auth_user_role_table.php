<?php
/**
 * 创建用户-角色中间表（多态关联）
 *
 * 通过 user_type + user_id 支持多用户类型
 * （如 admin 和 member 使用不同的用户表）。
 */
use think\migration\Migrator;
use think\migration\db\Column;

class CreateAuthUserRoleTable extends Migrator
{
    protected function getTable(): string
    {
        return 'auth_user_role';
    }

    public function up(): void
    {
        $tableName = $this->getTable();

        $table = $this->table($tableName, [
            'engine'    => 'InnoDB',
            'comment'   => '用户-角色关联表（多态）',
            'collation' => 'utf8mb4_unicode_ci',
        ]);

        if ($table->exists()) {
            return;
        }

        $table->addColumn(Column::string('user_type', 50)->setDefault('admin')->setComment('用户类型标识（admin/member等）'))
            ->addColumn(Column::integer('user_id')->setComment('用户ID'))
            ->addColumn(Column::integer('role_id')->setComment('角色ID'))
            // 数据权限扩展：可为特定用户-角色关联附加数据范围
            ->addColumn(Column::text('data_scope')->setNullable()->setComment('数据权限范围（JSON），如部门ID列表'))
            // 过期时间
            ->addColumn(Column::dateTime('expired_at')->setNullable()->setComment('角色过期时间'))
            // 时间戳
            ->addColumn(Column::dateTime('create_time')->setComment('创建时间'))
            ->addColumn(Column::dateTime('update_time')->setNullable()->setComment('更新时间'))
            // 索引
            ->addIndex(['user_type', 'user_id'])
            ->addIndex('role_id')
            ->addIndex(['user_type', 'user_id', 'role_id'], ['unique' => true])
            ->create();
    }

    public function down(): void
    {
        $tableName = $this->getTable();

        if ($this->table($tableName)->exists()) {
            $this->table($tableName)->drop()->save();
        }
    }
}
