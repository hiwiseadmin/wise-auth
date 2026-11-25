<?php
declare(strict_types=1);

use think\migration\Migrator;
use think\migration\db\Column;

/**
 * 安全事件日志表
 */

class CreateSecurityEventsTable extends Migrator
{
    protected function getTable(): string
    {
        return 'auth_security_events';
    }

    public function up(): void
    {
        $table = $this->table($this->getTable(), [
            'engine' => 'InnoDB',
            'comment' => '安全事件日志表',
            'collation' => 'utf8mb4_unicode_ci',
        ]);

        $table->addColumn(Column::string('event_type', 50)->setNull(false)->setComment('事件类型'))
              ->addColumn(Column::string('username', 100)->setNull(true))
              ->addColumn(Column::string('ip', 45)->setNull(true))
              ->addColumn(Column::string('user_agent', 500)->setNull(true))
              ->addColumn(Column::text('details')->setNull(true)->setComment('JSON 详情'))
              ->addColumn(Column::dateTime('create_time')->setNull(false)->setComment('创建时间'))
              ->addIndex(['event_type'])
              ->addIndex(['username'])
              ->addIndex(['ip'])
              ->addIndex(['create_time'])
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
