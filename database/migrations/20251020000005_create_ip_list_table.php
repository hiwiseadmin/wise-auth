<?php
declare(strict_types=1);

use think\migration\Migrator;
use think\migration\db\Column;

/**
 * IP 黑白名单表＼�
 *
 * 支持数据库方式管理 IP 黑白名单，便于后台动态管理。
 */
class CreateIpListTable extends Migrator
{
    protected function getTable(): string
    {
        return 'auth_ip_lists';
    }

    public function up(): void
    {
        $table = $this->table($this->getTable(), [
            'engine'    => 'InnoDB',
            'comment'   => 'IP 黑白名单表',
            'collation' => 'utf8mb4_unicode_ci',
        ]);

        $table->addColumn(Column::string('cidr', 45)->setNull(false)->setComment('CIDR 网段/IP'))
              ->addColumn(Column::string('type', 20)->setDefault('black')->setNull(false)->setComment('类型：whitelist/blacklist'))
              ->addColumn(Column::string('remark', 200)->setDefault('')->setNull(false)->setComment('备注'))
              ->addColumn(Column::tinyInteger('status')->setDefault(1)->setNull(false)->setComment('状态：1启用 0禁用'))
              ->addColumn(Column::dateTime('create_time')->setNull(false)->setComment('创建时间'))
              ->addColumn(Column::dateTime('update_time')->setNull(false)->setComment('更新时间'))
              ->addIndex(['cidr', 'type'], ['unique' => true])
              ->addIndex(['type', 'status'])
              ->create();
    }

    public function down(): void
    {
        $tableName = $this->getTable();

        if ($this->hasTable($tableName)) {
            $this->table($tableName)->drop()->save();
        }
    }
}
