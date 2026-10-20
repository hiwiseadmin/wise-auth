<?php
/**
 * 创建权限表
 *
 * 权限细分为"权限规则"，可存储路由、请求方法、条件等。
 * 支持树形权限结构（parent_id）。
 */
use think\migration\Migrator;
use think\migration\db\Column;

class CreateAuthPermissionsTable extends Migrator
{
    protected function getTable(): string
    {
        return 'auth_permissions';
    }

    public function up(): void
    {
        $tableName = $this->getTable();

        $table = $this->table($tableName, [
            'engine'    => 'InnoDB',
            'comment'   => '权限规则表',
            'collation' => 'utf8mb4_unicode_ci',
        ]);

        if ($table->exists()) {
            return;
        }

        $table->addColumn(Column::string('ident', 100)->setUnique()->setComment('权限标识（唯一，如 admin.user.list）'))
            ->addColumn(Column::string('name', 100)->setComment('权限名称'))
            ->addColumn(Column::string('description', 255)->setDefault('')->setComment('权限描述'))
            ->addColumn(Column::string('type', 20)->setDefault('route')->setComment('权限类型：route/api/custom'))
            ->addColumn(Column::string('route', 200)->setDefault('')->setComment('路由路径（支持通配符*）'))
            ->addColumn(Column::string('method', 20)->setDefault('*')->setComment('允许的请求方法（GET/POST/PUT/DELETE/*）'))
            ->addColumn(Column::integer('parent_id')->setDefault(0)->setComment('父权限ID'))
            ->addColumn(Column::string('path', 500)->setDefault('')->setComment('树形路径'))
            ->addColumn(Column::integer('level')->setDefault(0)->setComment('层级深度'))
            ->addColumn(Column::string('plugin', 50)->setDefault('')->setComment('所属插件标识'))
            ->addColumn(Column::string('source', 20)->setDefault('database')->setComment('来源：database/config/attribute'))
            ->addColumn(Column::json('conditions')->setNullable()->setComment('权限条件（JSON），如自定义规则'))
            ->addColumn(Column::integer('sort')->setDefault(0)->setComment('排序'))
            ->addColumn(Column::tinyInteger('status')->setDefault(1)->setComment('状态(1:启用 0:禁用)'))
            ->addColumn(Column::text('extend')->setNullable()->setComment('扩展属性（JSON）'))
            ->addColumn(Column::dateTime('create_time')->setComment('创建时间'))
            ->addColumn(Column::dateTime('update_time')->setNullable()->setComment('更新时间'))
            ->addColumn(Column::dateTime('delete_time')->setNullable()->setComment('删除时间（软删除）'))
            ->addIndex('ident', ['unique' => true])
            ->addIndex('type')
            ->addIndex('parent_id')
            ->addIndex('status')
            ->addIndex('plugin')
            ->addIndex(['route', 'method'])
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
