<?php
/**
 * 创建权限角色表
 *
 * 支持 RBAC1 角色继承（parent_id 父子角色字段）。
 */
use think\migration\Migrator;
use think\migration\db\Column;

class CreateAuthRolesTable extends Migrator
{
    protected function getTable(): string
    {
        $name = config('wise-auth.table_names.roles', 'auth_roles');
        return $name;
    }

    public function up(): void
    {
        $tableName = $this->getTable();

        $table = $this->table($tableName, [
            'engine'    => 'InnoDB',
            'comment'   => '权限角色表',
            'collation' => 'utf8mb4_general_ci',
        ]);

        if ($table->exists()) {
            return;
        }

        $table->addColumn(Column::string('name', 50)->setComment('角色名称'))
            ->addColumn(Column::string('slug', 50)->setUnique()->setComment('角色标识（唯一）'))
            ->addColumn(Column::string('description', 255)->setDefault('')->setComment('角色描述'))
            ->addColumn(Column::integer('parent_id')->setDefault(0)->setComment('父角色ID（RBAC1继承）'))
            ->addColumn(Column::string('path', 500)->setDefault('')->setComment('树形路径（如 0-1-3）'))
            ->addColumn(Column::integer('level')->setDefault(0)->setComment('层级深度'))
            ->addColumn(Column::tinyInteger('is_inherit')->setDefault(1)->setComment('是否继承父角色权限(1:是 0:否)'))
            ->addColumn(Column::integer('sort')->setDefault(0)->setComment('排序'))
            ->addColumn(Column::tinyInteger('status')->setDefault(1)->setComment('状态(1:启用 0:禁用)'))
            ->addColumn(Column::text('extend')->setNullable()->setComment('扩展属性（JSON）'))
            ->addColumn(Column::dateTime('create_time')->setComment('创建时间'))
            ->addColumn(Column::dateTime('update_time')->setNullable()->setComment('更新时间'))
            ->addColumn(Column::dateTime('delete_time')->setNullable()->setComment('删除时间（软删除）'))
            ->addIndex('parent_id')
            ->addIndex('status')
            ->addIndex('slug', ['unique' => true])
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
