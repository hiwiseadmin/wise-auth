<?php
/**
 * 创建角色-权限中间表
 */
use think\migration\Migrator;
use think\migration\db\Column;

class CreateAuthRolePermissionTable extends Migrator
{
    protected function getTable(): string
    {
        return 'auth_role_permission';
    }

    public function up(): void
    {
        $tableName = $this->getTable();

        $table = $this->table($tableName, [
            'engine'    => 'InnoDB',
            'comment'   => '角色-权限关联表',
            'collation' => 'utf8mb4_unicode_ci',
            'id'        => false
        ]);

        if ($table->exists()) {
            return;
        }

        $table->addColumn(Column::integer('role_id')->setNullable(false)->setComment('角色ID'))
            ->addColumn(Column::integer('permission_id')->setNullable(false)->setComment('权限ID'))
            ->changePrimaryKey(['role_id', 'permission_id'])
            ->addIndex('role_id')
            ->addIndex('permission_id')
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
